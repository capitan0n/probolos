# Roadmap to 1.0.0

Until 1.0.0 nothing new goes in: every change is a fix, a security fix,
testing, documentation or release work. The features of 1.0 are the ones in
the tree; what is left is making them correct, proven and documented. That is
also what the thesis needs: one fixed system, and the evidence that it does
what it claims.

---

## 1. The freeze

### 1.1 What 1.0 is

`CAPABILITIES.md` §1 as of the `v0.11.0` tag: the closed gate; the four
stages; the human decision (one dialog, two, or the countdown); the trust
store, including "always" under `--privsep`; history and drift detection;
holding devices behind a locked screen or with no agent; privilege
separation; lockout safety; `--watch-media`; and the systemd service.

### 1.2 What 1.0 is not

Deferred, and recorded in `CAPABILITIES.md` §3.0 so the decision is visible:

| Deferred | Was |
|---|---|
| A GUI for history and trust | T5 |
| `--remove-history N\|PATTERN`, numbered `--history` | T7 |
| A configurable dialog timeout (60 s stays) | T8 |
| HID report-descriptor analysis | `CAPABILITIES.md` §3.2 |
| `--close-race-window` | stays in the tree, experimental, outside the 1.0 guarantees |

### 1.3 What counts as a fix

A change that makes documented behaviour true is a **fix**. A change that adds
behaviour is a **feature** and waits for after 1.0.

| Allowed | Not allowed |
|---|---|
| bug fixes, including a false positive or negative on real hardware | new command-line options |
| security fixes | new analyzers or rules (a rule that misfires may be *fixed*) |
| tests, CI, linters, coverage | new UI or new prompts |
| documentation | a behaviour change that is not a fix |
| packaging, release engineering | refactoring that no fix needs |

**In doubt?** Open an issue labelled `post-1.0` and move on.

---

## 2. Versions

| Stage | Versions | Enter when | Leave when |
|---|---|---|---|
| Freeze | `0.11.0` to `0.13.0` | 2026-10-03 | Phase 1 done |
| Beta | `1.0.0b1`, `b2`, … | hardening done | no open P0/P1, hardware matrix passed, docs complete |
| Release candidate | `1.0.0rc1`, … | beta exit met | two quiet weeks with no change |
| Final | `1.0.0` | the last rc, unchanged | — |

- Versions follow PEP 440, and pacman sorts them the same way
  (`1.0.0b1 < 1.0.0b10 < 1.0.0rc1 < 1.0.0`).
- Bump the version in `pyproject.toml` *and* in the fallback in
  `probolos/__init__.py`.
- Tag each release with a signed tag (`git tag -s`) on a commit of `main`;
  `release.yml` refuses any other.
- Every tag from `1.0.0b1` on goes to PyPI once the maintainer approves the
  upload (1.14). A file on PyPI can never be uploaded again, even after it is
  deleted: a bad upload means a new version.

---

## 3. Steps

**M** = must, **S** = should, **C** = could.

### Phase 0: freeze

- [x] **0.1 M** Write the changelog for the freeze; release it as `0.11.0`.
- [x] **0.2 M** Add the feature-freeze note to `CAPABILITIES.md` and move the
  deferred items to its §3.
- [x] **0.3 M** Tag `v0.11.0`, the feature-complete snapshot the thesis
  describes.
- [ ] **0.4 S** Set up GitHub: labels, milestones, private vulnerability
  reporting, secret scanning with push protection, and issue templates
  (`docs/GITHUB-SETUP.md`).
- [ ] **0.5 M** Open one issue for every Phase 1 item.

### Phase 1: hardening → `1.0.0b1`

- [x] **1.1 M** Test the gate's refusal paths; boundary coverage at least 90%
  (it reached 95%), with the floor in `coverage.yml` raised to match.
- [x] **1.2 M** Remove dead code: the agent's CRITICAL message said "Use the
  terminal" (made true instead).
- [x] **1.3 M** Bring `SECURITY.md` up to date: the gate-side trust write,
  holding, the text cut, dialog exit codes.
- [ ] **1.4 M** Before every beta, run the deep property tests
  (`HYPOTHESIS_PROFILE=deep`); they must be clean.
- [ ] **1.5 S** End-to-end test on a real kernel: a QEMU VM with `dummy_hcd`
  and `raw_gadget`, so a fake keyboard and a fake stick meet the real service.
  A scripted manual run before each beta is enough.
- [x] **1.6 S** Review everything since `0.10.0`, root side first, and log
  every finding (§6). Done 2026-10-04; fixed in 0.12.0 except 1.11 to 1.13.
- [x] **1.7 S** Leave hardware- and GUI-only modules out of coverage, with the
  reason next to the setting, and re-baseline the floors.
- [ ] **1.8 S** Package (T6): finish the `PKGBUILD`, then build, install and
  uninstall it cleanly on Manjaro.
- [x] **1.9 S** Release workflow: on a `v*` tag, build the sdist and wheel,
  write `SHA256SUMS`, attest provenance, and create a **draft** pre-release.
- [x] **1.10 C** Run mypy on the root-side modules.
- [x] **1.11 M** The shared `nobody` account must not be able to open the
  gate (any `nobody` process could kill the analyzer, and the gate reopens on
  any analyzer exit). P1. Done in 0.13.0: the service runs the analyzer as
  `probolos`. Keeping the hubs closed instead was not taken
  (`docs/TECHNICAL-REFERENCE.md` says why).
- [x] **1.12 S** Reap the analyzer's whole process tree: a subreaper in the
  gate, so nothing the analyzer forked outlives it on a terminal run. P1.
  The analyzer's exit also ends the gate when a process it left behind holds
  its socket.
- [x] **1.13 S** The agent socket: another process with the analyzer's uid can
  take its place. P2. Root binds the socket before the privilege drop, in a
  directory root owns; the analyzer inherits the listener.
- [ ] **1.14 S** Publish to PyPI by trusted publishing: TestPyPI at once, PyPI
  when the maintainer approves. The workflow is done; the publishers and
  environments are set up by hand (`docs/GITHUB-SETUP.md`). Done when
  `1.0.0b1` is on PyPI.

**Exit:** every M item done, every S item done or consciously moved, CI green.
Then tag `1.0.0b1`, approve the PyPI upload and publish the pre-release. (The
version was bumped to `1.0.0b1` on 2026-10-09.)

### Phase 2: beta (`1.0.0b1`, `b2`, …)

- [ ] **2.1 M** Use it yourself: run the service daily for at least four
  weeks and open an issue for every surprise.
- [ ] **2.2 M** Run the hardware matrix (T9) and record it in a new
  `TESTING.md`:
  - **desktops:** KDE on Wayland and X11, and GNOME; each with and without tk;
  - **devices:** USB stick, keyboard, mouse, phone (MTP and tethering), hub,
    card reader;
  - **flows:** install, plug, allow, refuse, a refused device getting the
    countdown, two copies refused, `--remove-all`, reboot, plugging in at the
    login screen, uninstall.
- [ ] **2.3 M** Docs (T10): `README.md` and `systemd/README.md` ordered for
  the service user (install → plug → answer), and screenshots of the three
  prompt levels.
- [ ] **2.4 M** Take the thesis measurements (`CAPABILITIES.md` §3.1),
  scripted and repeatable: keystrokes that escape before the grab
  (`testbed/hidexp/EXPERIMENT.md`), detection and miss rates, false positives
  on ordinary devices, how long each stage takes, recovery after failures.
- [ ] **2.5 S** Cut the next beta when fixes pile up.

**Exit:** no open P0/P1; the matrix passed on at least two desktops; the docs
are complete.

### Phase 3: release candidate (`1.0.0rc1`)

- [ ] **3.1 M** The docs freeze too. Only P0 and security fixes go in, and
  each one means a new rc.
- [ ] **3.2 M** Final checks: the deep property run, coverage floors,
  actionlint and zizmor, a five-flow hardware smoke test, a fresh package
  install on a clean VM.
- [ ] **3.3 M** Two weeks with no change at all.

### Phase 4: `1.0.0`

- [ ] **4.1 M** The last rc plus the version number: changelog date, signed
  tag, a GitHub release (not a pre-release), the approved PyPI upload, and the
  AUR package if 1.8 was done.
- [ ] **4.2 S** Archive it for citation: Software Heritage, and a Zenodo DOI
  for the release, cited in the thesis.
- [ ] **4.3 C** After 1.0, new features go to `main` for 1.1; a `maint/1.0`
  branch only if 1.0 needs fixes meanwhile.

---

## 4. Priorities

| Level | Means | Blocks |
|---|---|---|
| **P0** | Fail-open (anything admitted without a human answer); the gate left open or ports left dead after exit; privilege escalation; the service failing to start or crashing | every release |
| **P1** | A wrong verdict on common hardware; a lost decision; damage to the trust store or ledger; a security weakness without a known exploit | rc |
| **P2** | Rare edge cases, misleading messages, documentation errors | fix if cheap |
| **P3** | Cosmetic | after 1.0 |

---

## 5. Every change

- [ ] An issue with a label and milestone; security issues go through a private
      advisory first.
- [ ] A regression test that fails before the fix and passes after it.
- [ ] `python -m tests.run_all` and `ruff check .` pass locally, and CI is
      green, coverage floors included.
- [ ] A line in `CHANGELOG.md` under `Unreleased`.
- [ ] The docs corrected, if the bug was in what they promised.

Rules for an LLM agent working on this repo:

1. No commits, tags, pushes or releases unless asked for that exact action.
2. Hand over changed files as an archive.
3. `python -m tests.run_all` and `ruff check .` pass before handover.
4. **No features.** Anything that is not a fix goes to `post-1.0`.

---

## 6. The thesis evidence

`docs/QA-LOG.md` keeps one row per defect found: date, what, how it was found
(review, property test, fuzzing, hardware matrix, dogfooding or a user report),
severity and fix commit. With the coverage table and the matrix in
`TESTING.md`, that log is the data of the evaluation chapter: what each method
found, on a system that did not change underneath the measurement.
