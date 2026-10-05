# QA log

One row per defect found from the `v0.11.0` freeze on (ROADMAP §6). Together
with the coverage table below and the hardware matrix that will go in
`TESTING.md` (ROADMAP 2.2), this is the evaluation chapter's data: what each
method found, on a system that did not change underneath the measurement.

**How it was found** is one of: review, property test, static analysis,
hardware matrix, dogfooding, user report. "Review (structure audit)" is the
multi-reviewer audit of 2026-10-04: six independent reviewers, one per angle
(packaging, documentation, paths, tests, CI, release readiness), each finding
re-checked by a separate skeptic before it was accepted. "Review (fix
verification)" is the same method applied to the batch of fixes that followed
it, which also checked the code those fixes describe. "Review (security
audit)" is the audit of 2026-10-04 that led to 0.12.0: four independent
reviewers (privilege boundary; device handling and parsers; decision flow,
CLI, agent and test quality; packaging, CI, install and documentation), each
finding reproduced by its reviewer where it could be, then re-checked against
the code by the integrating reviewer before it was accepted, and every fix
shown by a regression test that fails on 0.11.0. **Severity** follows
ROADMAP §4 (P0–P3). **Fix commit** is filled in once the fix is committed;
"open" means not fixed in 0.12.0.

| Date | What | How it was found | Severity | Fix commit |
|---|---|---|---|---|
| 2026-10-03 | `textsafe` cut skipped an escape and kept appending (`'\x1f0'` at limit 1 came out as `0...`) | property test, unaided | P2 | `ecb6453` |
| 2026-10-03 | The agent's `MSG_CRITICAL` handler told the person "cannot be approved from here. Use the terminal": untrue since CRITICAL devices got the countdown, and the service has no terminal. `AgentLink.notify_critical` had no caller | review | P2 | `aa2a0d3` |
| 2026-10-03 | `SECURITY.md` said an unanswered agent question "times out into the terminal fallback" and that stores are always created `0600`; neither has been true since the service hold and the gate-side trust write | review | P2 | `aa2a0d3` |
| 2026-10-04 | `CAPABILITIES.md` §1, the 1.0 feature contract, left out nine rules the code emitted at `v0.11.0` (five CRITICAL), listed a tenth only in §3.4, and said nothing of `analyzer-failed:<check>` or the systemd service | review (structure audit) | P2 | |
| 2026-10-04 | `CAPABILITIES.md` §1.6 said both state files are written at `0600`; under `--privsep` the trust store is made `0644` | review | P2 | |
| 2026-10-04 | `CAPABILITIES.md` §1.12 said the report's `_line()` uses `textsafe.pad()` and a new `_field()`; neither function exists any more, nothing outside the tests calls `pad()`, and §2.2 did not list the now unreachable `pad`/`fit` | review (structure audit) | P2 | |
| 2026-10-04 | `CAPABILITIES.md` pointed to an `AUDIT_REPORT_EL.md` that is not in the repository | review (structure audit) | P3 | |
| 2026-10-04 | `CAPABILITIES.md` §1.11 came after §1.12 and §1.13 | review (structure audit) | P3 | |
| 2026-10-04 | `systemd/README.md` "By hand" install: without `WorkingDirectory=/` and `PYTHONPATH` the agent could not import `probolos`; with the shipped `PROBOLOS_AGENT_USER=nobody` the gate turned the agent off and denied every device | review (structure audit) | P2 | |
| 2026-10-04 | `systemd/README.md` called the privileged half "about 150 auditable lines", which README.md already retracts (`gate_server.py` alone is over 1200) | review (structure audit) | P3 | |
| 2026-10-04 | The bug-report form and `SECURITY.md` asked for `probolos --version`, which the CLI rejects | review (structure audit) | P2 | |
| 2026-10-04 | `SECURITY.md` referred to an inhibitor file "not present in the supplied ZIP", a ZIP that is not part of the repository | review (structure audit) | P3 | |
| 2026-10-04 | `testbed` preset `overpowered` crashed before presenting anything: 800 mA does not fit `bMaxPower` (one byte, 2 mA units) | review (structure audit) | P2 | |
| 2026-10-04 | `modprobe dummy_hcd raw_gadget`, in five places, loads only `dummy_hcd` (the second name becomes a module option) | review (structure audit) | P2 | |
| 2026-10-04 | `install.sh` put the checkout path into Python source; a path with a quote made it a syntax error, which read as "not running" and skipped the already-running check | review (structure audit) | P2 | |
| 2026-10-04 | The sdist shipped the test modules without `tests/__init__.py`, `_support.py`, `_media.py` or `run_all.py`, so its tests could not run | review (structure audit) | P2 | |
| 2026-10-04 | `testbed/hidexp/EXPERIMENT.md` predicted zero leaked keystrokes with `--close-race-window`, which CAPABILITIES §1.4 rules out, pre-filled its results table, used personal paths, and was linked from nowhere | review (structure audit) | P2 | |
| 2026-10-04 | The release build floated its backend although its pin file promised "same tag, same build" | review (structure audit) | P3 | |
| 2026-10-04 | `coverage` was pinned without its TOML extra, which Python 3.10 needs to read the config | review (structure audit) | P3 | |
| 2026-10-04 | README.md's test table missed `test_boundary.py` and `test_properties.py` | review (structure audit) | P3 | |
| 2026-10-04 | README.md pointed to "known open items" in CHANGELOG.md, which lists none | review (structure audit) | P3 | |
| 2026-10-04 | A comment in `daemon.py` recommended a `--trust` flag that does not exist | review (structure audit) | P3 | |
| 2026-10-04 | Stale comments: `report.py` described itself as an alternative to itself (`report1`), `textsafe.py` cited a report box that is gone, the `pyproject.toml` console-script comment described units that do not use it, and two test comments named deleted test modules | review (structure audit) | P3 | |
| 2026-10-04 | `tests/run_all.py` wrapped module-level test functions that `unittest discover` does not collect, hiding the difference README.md calls a bug | review (structure audit) | P3 | |
| 2026-10-04 | The report-width tests checked only lines starting with a box border; with the box gone they checked no line at all | review (fix verification) | P3 | |
| 2026-10-04 | `SECURITY.md` said only a trust store the gate creates is `0644`; the `--privsep` launcher also makes an existing one `0644`, and rewrites keep it | review (fix verification) | P3 | |
| 2026-10-04 | Three workflows had no job timeout | review (structure audit) | P3 | |
| 2026-10-04 | The tkinter fallback asked "Allow it?" with Yes/No/Cancel and mapped No to "Always allow": the refusal button admitted the device and trusted it for good | review (security audit) | P1 | |
| 2026-10-04 | Stage 3 and 4 switched a device on by path, so a device that re-enumerated at the same port after the identity checks was activated in the inspected one's place (stage 4: no input grab) | review (security audit) | P1 | |
| 2026-10-04 | `sysfs.read_attr` decoded with the locale and raised `UnicodeDecodeError` past its `OSError` handler; at startup it escaped `snapshot()` and the gate reopened as the process exited | review (security audit) | P0 | |
| 2026-10-04 | The `--privsep` analyzer inherited the instance-lock descriptor (`O_CLOEXEC` acts at exec, not fork) and could release it, so a second gate could start | review (security audit) | P2 | |
| 2026-10-04 | The analyzer accepted a trust store owned by its own uid, the shared `nobody`, which the gate refuses (non-default `--trust-file` only) | review (security audit) | P2 | |
| 2026-10-04 | After the watchdog reopened the gate the process exited 0, so `Restart=on-failure` never restarted it and the unit read inactive | review (security audit) | P1 | |
| 2026-10-04 | `--release` ran under a live gate, admitting what it held or had refused and reopening the hubs; it also exited 0 on failed writes | review (security audit) | P2 | |
| 2026-10-04 | `--release` with no blocked device returned before resetting the hubs, so a gate left closed by a `SIGKILL` with nothing plugged in stayed closed | review (fix verification) | P1 | |
| 2026-10-04 | `--remove-trusted ""` fell through every command and started the gate; two commands ran only the first; `--dry-run` with `--release`/`--remove-*` changed state, and `--dry-run --privsep` chmodded the trust store and handed over the ledger directory | review (security audit) | P2 | |
| 2026-10-04 | Direct-mode "always" rewrote a trust store that had failed to load, keeping only what was read plus the new entry | review (security audit) | P1 | |
| 2026-10-04 | `TrustStore.save` returned success for a failure that repeated the previous one, so the second unsaved "always" printed "remembered" | review (security audit) | P2 | |
| 2026-10-04 | kdialog/zenity `notice()` read every exit as "closed", so a countdown window that crashed at once was recorded as a refusal (arming `previously-rejected`) | review (security audit) | P2 | |
| 2026-10-04 | The agent died on deeply nested JSON (`RecursionError` in `_handle`) | review (security audit) | P3 | |
| 2026-10-04 | `--history` on an unreadable ledger printed "History is empty" | review (security audit) | P2 | |
| 2026-10-04 | `install.sh` copied symlinks from the checkout into root-owned `/opt/probolos` (the package directory itself included), so the root service could run code its owner could still edit | review (security audit) | P1 | |
| 2026-10-04 | `install.sh` ran `python -c 'import pyudev'` and `-m compileall` as root without `-I`, from the caller's directory | review (security audit) | P2 | |
| 2026-10-04 | `install.sh --user 0` passed the root check (the service then restarted forever); a trailing `--user` exited with no message; uninstall deleted an administrator's `override.conf`; the code was deleted before its replacement was moved in | review (security audit) | P2 | |
| 2026-10-04 | `release.yml` built and attested a draft for any `v*` tag on any commit, without the checks; pre-release status was a pattern on the tag (`.devN` read as final); `1.0.0-beta.1` matched its tag and built `1.0.0b1` files | review (security audit) | P2 | |
| 2026-10-04 | `SECURITY.md` said the `2750` agent directory kept out other `nobody` processes (it only removed group write) and listed "analyzer compromise cannot escalate to root" as a lockout layer; the last-resort command reset only `usb1` | review (security audit) | P2 | |
| 2026-10-04 | Docs: an emoji and `pip install pyudev` before `sudo python3` in README.md; "internal ports are never gated" without `--gate-fixed-ports`; recovery commands only for a checkout; "denied" for held devices in `systemd/README.md` and a stale unit comment; the testbed's CRITICAL line; `--forget` in SECURITY.md; `-v` help naming only `--list` | review (security audit) | P3 | |
| 2026-10-04 | Tests left 33 temporary directories per run, and `unittest.main()` mid-file in `test_trust.py`/`test_ledger.py` skipped later classes when a file was run directly | review (security audit) | P3 | |
| 2026-10-04 | Any process running as `nobody` can kill the `--privsep` analyzer; the gate then reopens every hub until the service restarts, and devices attached meanwhile become untouched baseline | review (security audit) | P1, open | |
| 2026-10-04 | A compromised analyzer's descendants outlive the gate on a terminal run (the terminal stays readable to them; one holding the socket keeps the gate serving) | review (security audit) | P1, open | |
| 2026-10-04 | Any `nobody` process can replace the agent socket and show the agent its own questions (it cannot approve anything) | review (security audit) | P2, open | |
| 2026-10-04 | `--timeout` under about 12 s disagrees with the agent's 10 s floor; the capped decision history can lose an old refusal; `--lock-policy deny` never asks about devices stranded at a locked start; `--agent` with a failed socket denies instead of holding | review (security audit) | P2, open | |

## Coverage (privilege boundary)

`coverage.yml`, as root, branch coverage, `HYPOTHESIS_PROFILE=ci`.

| Module | Tests | 0.11.0 | `aa2a0d3` |
|---|---|---|---|
| `protocol.py` | test_privsep, test_properties | 97% | 98% |
| `gate_server.py` | test_privsep, test_boundary | 81% | 95% |
| `gate_client.py` | test_privsep, test_boundary | 71% | 94% |
| `privsep.py` | test_privsep, test_boundary | 67% | 98% |
| `securefs.py` | test_privsep, test_trust | 87% | 87% |
| `atomicio.py` | test_trust, test_ledger | 85% | 85% |
| **boundary** | | **80%** | **95%** |
| **total** (without `interrogate.py`, `countdown_dialog.py`) | | 81%¹ | 85% |

¹ Measured with the two modules included.

## Deep property runs (ROADMAP 1.4)

| Date | Version | `HYPOTHESIS_PROFILE=deep` | Result |
|---|---|---|---|
| 2026-10-03 | `aa2a0d3` (0.11.0 and the first Phase 1 batch) | 26 property tests, 7500 examples each, Python 3.11 | Clean, 630 s; nothing found |
| 2026-10-04 | `ed0ad1a` (before the 0.12.0 fixes) | 26 property tests, 7500 examples each, Python 3.11 | Clean, 659 s; nothing found |
| 2026-10-04 | 0.12.0 working tree, uncommitted (the audit's fixes on `ed0ad1a`) | 26 property tests, 7500 examples each, Python 3.11 | Clean, 620 s; nothing found. Repeat on the commit tagged `v0.12.0` |

## Mutation testing

2026-10-04, security audit: 48 hand-made mutants of the decision path, each
run against the whole suite. 15 survived. The ones that weakened a security
contract now have a test that kills them (`ShortcutsNeverOutrankACriticalFinding`
in `test_daemon.py`): trust admitting past a CRITICAL finding, `y` passing a
CRITICAL terminal prompt, stage 4 not re-blocking, `--dry-run` admitting a
protected device or writing the ledger. The rest are redundant defence layers
or messages (e.g. the pre-ask drain, the `_asking` guard), left as they are.

## Static analysis

Findings from tools that are not part of the suite. A false positive is not a
defect and gets no row above, but it is part of what each method found.

| Date | Tool | Finding | Verdict |
|---|---|---|---|
| 2026-10-03 | CodeQL (GitHub default setup) | `py/clear-text-logging-sensitive-data` at `probolos/__main__.py:292` and `:296` (`--remove-trusted` output) | False positive, both: they print the operator's own argument and a device identity (`VID:PID:serial`) to the operator's terminal, the same data `--trusted` lists; Probolos holds no secrets |
