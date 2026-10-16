# QA log

One row per defect found since the `v0.11.0` freeze (ROADMAP §6): what it
was, how it was found, and how bad (ROADMAP §4, P0–P3). With the coverage
table below and the hardware matrix planned for `TESTING.md` (ROADMAP 2.2),
this is the data of the thesis's evaluation chapter.

**How it was found:** review, property test, static analysis, hardware matrix,
dogfooding or user report. The reviews:

- *structure audit* (2026-10-04): six reviewers, one per angle (packaging,
  documentation, paths, tests, CI, release readiness), each finding re-checked
  by a separate skeptic;
- *security audit* (2026-10-04, led to 0.12.0): four reviewers (privilege
  boundary; device handling and parsers; decision flow, CLI and agent;
  packaging, CI, install and docs); findings reproduced where possible and
  re-checked against the code, and every fix shown by a test that fails on
  0.11.0;
- *fix verification*: the same method applied to a batch of fixes.

**Fix commit** is filled in once the fix is committed; "open" means not fixed
yet.

| Date | What | How it was found | Severity | Fix commit |
|---|---|---|---|---|
| 2026-10-03 | `textsafe` cut skipped an escape and kept appending (`'\x1f0'` at limit 1 came out as `0...`) | property test, unaided | P2 | `ecb6453` |
| 2026-10-03 | The agent's CRITICAL message said "Use the terminal", untrue since the countdown and with no terminal under the service; `AgentLink.notify_critical` had no caller | review | P2 | `aa2a0d3` |
| 2026-10-03 | `SECURITY.md` said an unanswered question falls back to the terminal and that stores are always `0600`; neither was true any more | review | P2 | `aa2a0d3` |
| 2026-10-04 | `CAPABILITIES.md` §1 left out nine rules the code emitted (five CRITICAL), listed a tenth only in §3.4, and omitted `analyzer-failed:<check>` and the systemd service | review (structure audit) | P2 | |
| 2026-10-04 | `CAPABILITIES.md` §1.6 said both state files are `0600`; under `--privsep` the trust store is `0644` | review | P2 | |
| 2026-10-04 | `CAPABILITIES.md` §1.12 described report functions that no longer exist, and §2.2 did not list the now unused `textsafe.pad`/`fit` | review (structure audit) | P2 | |
| 2026-10-04 | `CAPABILITIES.md` pointed to an `AUDIT_REPORT_EL.md` that is not in the repository | review (structure audit) | P3 | |
| 2026-10-04 | `CAPABILITIES.md` §1.11 came after §1.12 and §1.13 | review (structure audit) | P3 | |
| 2026-10-04 | `systemd/README.md` "By hand": without `WorkingDirectory=/` and `PYTHONPATH` the agent could not import `probolos`; with the shipped `PROBOLOS_AGENT_USER=nobody` the gate turned the agent off and denied every device | review (structure audit) | P2 | |
| 2026-10-04 | `systemd/README.md` called the privileged half "about 150 auditable lines" (`gate_server.py` alone is over 1200) | review (structure audit) | P3 | |
| 2026-10-04 | The bug-report form and `SECURITY.md` asked for `probolos --version`, which the CLI rejects | review (structure audit) | P2 | |
| 2026-10-04 | `SECURITY.md` referred to a ZIP that is not part of the repository | review (structure audit) | P3 | |
| 2026-10-04 | Testbed preset `overpowered` crashed: 800 mA does not fit `bMaxPower` | review (structure audit) | P2 | |
| 2026-10-04 | `modprobe dummy_hcd raw_gadget`, in five places, loads only `dummy_hcd` | review (structure audit) | P2 | |
| 2026-10-04 | `install.sh` put the checkout path into Python source; a quote in it made a syntax error that read as "not running" | review (structure audit) | P2 | |
| 2026-10-04 | The sdist shipped the tests without their helpers, so they could not run | review (structure audit) | P2 | |
| 2026-10-04 | `testbed/hidexp/EXPERIMENT.md` predicted zero leaked keystrokes with `--close-race-window` (CAPABILITIES §1.4 rules that out), pre-filled its results, used personal paths, and was linked from nowhere | review (structure audit) | P2 | |
| 2026-10-04 | The release build floated its backend despite its pin file | review (structure audit) | P3 | |
| 2026-10-04 | `coverage` was pinned without its TOML extra, which Python 3.10 needs | review (structure audit) | P3 | |
| 2026-10-04 | README.md's test table missed `test_boundary.py` and `test_properties.py` | review (structure audit) | P3 | |
| 2026-10-04 | README.md pointed to "known open items" in CHANGELOG.md, which lists none | review (structure audit) | P3 | |
| 2026-10-04 | A comment in `daemon.py` recommended a `--trust` flag that does not exist | review (structure audit) | P3 | |
| 2026-10-04 | Stale comments in `report.py`, `textsafe.py`, `pyproject.toml` and two tests | review (structure audit) | P3 | |
| 2026-10-04 | `tests/run_all.py` wrapped module-level test functions that `unittest discover` does not collect, hiding the difference README.md calls a bug | review (structure audit) | P3 | |
| 2026-10-04 | The report-width tests checked only lines starting with a box border; with the box gone they checked nothing | review (fix verification) | P3 | |
| 2026-10-04 | `SECURITY.md` said only a store the gate creates is `0644`; the launcher also makes an existing one `0644` | review (fix verification) | P3 | |
| 2026-10-04 | Three workflows had no job timeout | review (structure audit) | P3 | |
| 2026-10-04 | The tkinter fallback mapped "No" to "Always allow": the refusal button admitted and trusted the device | review (security audit) | P1 | |
| 2026-10-04 | Stages 3 and 4 switched a device on by path, so a device that re-enumerated at the same port was activated instead (stage 4: no input grab) | review (security audit) | P1 | |
| 2026-10-04 | `sysfs.read_attr` decoded with the locale and raised `UnicodeDecodeError` at startup; the gate reopened as the process exited | review (security audit) | P0 | |
| 2026-10-04 | The `--privsep` analyzer inherited the instance lock and could release it, so a second gate could start | review (security audit) | P2 | |
| 2026-10-04 | The analyzer accepted a trust store owned by the shared `nobody`, which the gate refuses (non-default `--trust-file` only) | review (security audit) | P2 | |
| 2026-10-04 | After the watchdog reopened the gate the process exited 0, so `Restart=on-failure` never restarted it | review (security audit) | P1 | |
| 2026-10-04 | `--release` ran under a live gate, admitting what it held and reopening the hubs; it exited 0 on failed writes | review (security audit) | P2 | |
| 2026-10-04 | `--release` with nothing blocked returned before resetting the hubs, so a gate left closed by `SIGKILL` stayed closed | review (fix verification) | P1 | |
| 2026-10-04 | `--remove-trusted ""` started the gate; two commands ran only the first; `--dry-run` with `--release`/`--remove-*` or `--privsep` changed state | review (security audit) | P2 | |
| 2026-10-04 | Direct-mode "always" rewrote a trust store that had failed to load, keeping only what was read plus the new entry | review (security audit) | P1 | |
| 2026-10-04 | `TrustStore.save` reported success for a repeated failure, so an unsaved "always" printed "remembered" | review (security audit) | P2 | |
| 2026-10-04 | kdialog/zenity `notice()` read every exit as "closed", so a crashed countdown window was recorded as a refusal | review (security audit) | P2 | |
| 2026-10-04 | The agent died on deeply nested JSON (`RecursionError`) | review (security audit) | P3 | |
| 2026-10-04 | `--history` on an unreadable ledger printed "History is empty" | review (security audit) | P2 | |
| 2026-10-04 | `install.sh` copied symlinks into root-owned `/opt/probolos`, so the root service could run code its owner could still edit | review (security audit) | P1 | |
| 2026-10-04 | `install.sh` ran Python as root without `-I`, from the caller's directory | review (security audit) | P2 | |
| 2026-10-04 | `install.sh`: `--user 0` passed the root check; a trailing `--user` exited silently; uninstall deleted an admin's `override.conf`; code was deleted before its replacement was moved in | review (security audit) | P2 | |
| 2026-10-04 | `release.yml` drafted a release for any `v*` tag on any commit, without the checks, and read pre-release status from the tag's pattern | review (security audit) | P2 | |
| 2026-10-04 | `SECURITY.md` overstated what the `2750` agent directory and privilege separation protect, and its last-resort command reset only `usb1` | review (security audit) | P2 | |
| 2026-10-04 | Docs: an emoji and `pip install pyudev` before `sudo python3`; "internal ports are never gated" without `--gate-fixed-ports`; recovery only for a checkout; "denied" for held devices; `--forget` in SECURITY.md; the testbed's CRITICAL line | review (security audit) | P3 | |
| 2026-10-04 | Tests left 33 temporary directories per run, and `unittest.main()` mid-file skipped later classes when a file was run directly | review (security audit) | P3 | |
| 2026-10-04 | Any process running as `nobody` can kill the `--privsep` analyzer, which reopens every hub; devices attached meanwhile become baseline. Fixed in 0.13.0 for the service; a run by hand still defaults to `nobody` | review (security audit) | P1 | |
| 2026-10-04 | A compromised analyzer's descendants outlive the gate on a terminal run | review (security audit) | P1 | |
| 2026-10-04 | Any `nobody` process can replace the agent socket and show the agent its own questions (it cannot approve anything). Fixed in 0.13.0 for the service; for a run by hand once root bound the socket | review (security audit) | P2 | |
| 2026-10-04 | `--timeout` under about 12 s disagrees with the agent's 10 s floor; the capped decision history can lose an old refusal; `--lock-policy deny` never asks about devices stranded at a locked start; `--agent` with a failed socket denies instead of holding | review (security audit) | P2 | |
| 2026-10-11 | `--watch-media` dropped a card the reader could not read (0 bytes after a media change) with no report and no audit entry | dogfooding | P2 | |
| 2026-10-11 | `--watch-media` reported `UDISKS_AUTO=0` as "automount inhibited"; KDE Plasma's automounter ignores it, and the README's udev rule relied on it | dogfooding | P2 | |
| 2026-10-11 | With `--watch-media` the plug-in prompt did not apply the card rules, and the approved card was judged again when its disk appeared; under `--media-policy deauthorize` the reader was switched off seconds after approval | dogfooding | P2 | |
| 2026-10-11 | Devices left switched off at exit (refused, or a reader switched off by the media policy) were not mentioned | dogfooding | P2 | |
| 2026-10-11 | `--watch-media` recorded a card's layout as the slot's reference before judging it, so a hostile first card became the baseline | review | P2 | |
| 2026-10-11 | `--history` showed an allow-listed device as AUTHORIZED and counted a screen-lock denial as a refusal; "first card seen in this slot" followed the run, not the history | review | P3 | |
| 2026-10-12 | The forked storage reader inherited the armed gate and its signal handlers: killed with `SIGTERM` after a stall, it reopened every root hub while the daemon believed the gate closed | review | P0 | |
| 2026-10-12 | `--watch-media` reported one card up to three times (the reader announcing it again, and stage 4's own disk events) | dogfooding | P3 | |
| 2026-10-12 | Stage 4 showed an isohybrid installer image only as "a large unused area" | dogfooding | P3 | |
| 2026-10-12 | `--history` cut serials to their first characters (`00000000`), hiding the part that tells devices apart | dogfooding | P3 | |
| 2026-10-12 | While the screen is locked, the internal-port and `--allow-port` exemptions do not apply (the lock check runs first), so a rescue keyboard plugged in at the lock screen stays blocked | review | P1 | |
| 2026-10-12 | Docs: `--timeout 0` was said to make a question wait (a dialog closes after 60 s); the unit's placeholder agent user was said to hold devices (they are refused after stages 3 and 4); closing a dialog was said to be no decision (it is "Keep blocked"); the panic file was not said to need the watchdog; `--lock-policy deny` stranding was not limited to runs without a desktop prompt | review | P2 | |
| 2026-10-12 | In the fixes above: the approval window started at registration, so a busy event loop lost the approval (under `deauthorize`, a switch-off); every unplug printed the "replaced reader" alarm; the re-announce line could hide new findings; a tiny ISO 9660 explained away a large gap; a planted ISO signature behind an MBR raised nothing | review (fix verification) | P2 | |
| 2026-10-14 | A process the analyzer forked kept the gate serving after the analyzer exited, for as long as it held the analyzer's end of the socket | review (fix verification) | P1 | |
| 2026-10-14 | A rescue keyboard left blocked by a run that died was queued at a locked start, and waited for the unlock it was needed for | review (fix verification) | P1 | |
| 2026-10-14 | zenity's exit 1 when GTK cannot open or loses the display was recorded as "Keep blocked", a refusal nobody made | review | P2 | |
| 2026-10-14 | At the 10 s floor the agent's first dialog stayed up a second after the analyzer stopped listening | review (fix verification) | P2 | |
| 2026-10-14 | The fixes of `a911831` (the storage reader reopening the gate, the card-reader watch fixes, isohybrid images, `--history` serials) were committed as `probolos-fixes.patch` and deleted in `3d659e7` unapplied; CHANGELOG.md and this log listed them as fixed | review | P0 | |
| 2026-10-14 | Under the shipped unit (no `CAP_KILL`) the gate's `SIGKILL` of an analyzer that outlived its socket failed with EPERM: root blocked in `waitpid` with the gate stopped and the unit active, then exited 0, so `Restart=on-failure` never ran | review | P1 | |
| 2026-10-15 | Under `--privsep` a Ctrl-C or hangup that landed just before the gate's blocking `recv()` was handled at C level without interrupting it, so the gate forwarded it only at the analyzer's next request (CI: `test_ctrl_c_at_the_terminal_still_reaches_the_analyzer`, about 1 in 30 under load) | CI failure, reproduced and root-caused | P2 | |
| 2026-10-15 | The same test raced on its own: its analyzer wrote "ready" outside its `try`, so a Ctrl-C forwarded at once ended it with the report cut to `ready ` (about 2 in 100 under load once the gate was fixed) | review (fix verification) | P3 | |
| 2026-10-15 | After the analyzer was reaped the gate still passed Ctrl-C, Ctrl-\\ and hangup on to its pid, which another process may have been given meanwhile | review (fix verification) | P3 | |

## Coverage (privilege boundary)

`coverage.yml`: as root, branch coverage, `HYPOTHESIS_PROFILE=ci`.

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

26 property tests, 7500 examples each.

| Date | Tree | Python | Result |
|---|---|---|---|
| 2026-10-03 | `aa2a0d3` (0.11.0 and the first Phase 1 batch) | 3.11 | clean, 630 s |
| 2026-10-04 | `ed0ad1a` (before the 0.12.0 fixes) | 3.11 | clean, 659 s |
| 2026-10-04 | the 0.12.0 working tree, uncommitted | 3.11 | clean, 620 s; repeat on the `v0.12.0` commit |
| 2026-10-09 | the 1.0.0b1 working tree, uncommitted (no code change since 0.13.0) | 3.13, Hypothesis 6.168.3 | clean, 727 s; repeat on the `v1.0.0b1` commit |

## Mutation testing

2026-10-04, security audit: 48 hand-made mutants of the decision path, each
run against the whole suite; 15 survived. Those that weakened a security
contract now have a test that kills them (`ShortcutsNeverOutrankACriticalFinding`
in `test_daemon.py`): trust admitting past a CRITICAL finding, `y` passing a
CRITICAL terminal prompt, stage 4 not re-blocking, `--dry-run` admitting a
protected device or writing the ledger. The rest are redundant defence layers
or messages, left as they are.

## Static analysis

Findings from tools outside the suite. A false positive is not a defect and
gets no row above, but it is part of what each method found.

| Date | Tool | Finding | Verdict |
|---|---|---|---|
| 2026-10-03 | CodeQL (default setup) | `py/clear-text-logging-sensitive-data` at `probolos/__main__.py:292` and `:296` (`--remove-trusted` output) | False positive, both: the operator's own argument and a device identity printed to the operator's terminal, as `--trusted` does; Probolos holds no secrets |
