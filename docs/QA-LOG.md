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
it, which also checked the code those fixes describe. **Severity** follows
ROADMAP §4 (P0–P3). **Fix commit** is filled in once the fix is committed.

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

## Static analysis

Findings from tools that are not part of the suite. A false positive is not a
defect and gets no row above, but it is part of what each method found.

| Date | Tool | Finding | Verdict |
|---|---|---|---|
| 2026-10-03 | CodeQL (GitHub default setup) | `py/clear-text-logging-sensitive-data` at `probolos/__main__.py:292` and `:296` (`--remove-trusted` output) | False positive, both: they print the operator's own argument and a device identity (`VID:PID:serial`) to the operator's terminal, the same data `--trusted` lists; Probolos holds no secrets |
