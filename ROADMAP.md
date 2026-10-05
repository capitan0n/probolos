# Probolos: the road to 1.0.0

From here on, nothing new goes in. Every change before 1.0.0 is a fix, a
security fix, testing, documentation or release work. The features that ship
in 1.0 are the ones in the tree today; the work left is making them correct,
proven and documented. A thesis needs that too: it describes one fixed system
and the evidence that the system does what it claims.

---

## 1. The freeze

### 1.1 What 1.0 is

**`CAPABILITIES.md` §1, as of the `v0.11.0` tag, is the feature contract.**
That covers:

- the closed gate;
- the four analysis stages;
- the human decision, by terminal or desktop agent, with one dialog, two, or
  the countdown;
- the trust store, including "always" under `--privsep`;
- the ledger and drift detection;
- holding devices behind a locked screen or with no agent;
- privilege separation;
- lockout safety;
- `--watch-media`;
- the systemd service.

### 1.2 What 1.0 is not

These are deferred to after 1.0. Record them in `CAPABILITIES.md` §3 so the
decision is visible:

| Deferred | Was |
|---|---|
| A GUI for history and trust | T5 |
| `--remove-history N\|PATTERN`, numbered `--history` | T7 |
| A configurable dialog timeout (60 s stays the default) | T8 |
| HID report-descriptor analysis | `CAPABILITIES.md` §3.2 |
| `--close-race-window` (deferred binding) | Stays in the tree, marked experimental, outside the 1.0 guarantees |

### 1.3 What counts as a fix

A change that makes documented behaviour true is a **fix**. A change that adds
behaviour is a **feature**, and goes on the post-1.0 list.

| Allowed | Not allowed |
|---|---|
| bug fix, including a false positive or negative on real hardware | new command-line options |
| security fix | new analyzers or rules (a rule that misfires may be *fixed*) |
| tests, CI, linters, coverage | new UI or new prompts |
| documentation | a behaviour change that is not a fix |
| packaging, release engineering | refactoring without a fix that needs it |

**In doubt?** Open an issue, label it `post-1.0`, and move on.

---

## 2. Versions and gates

| Stage | Version | Enter when | Leave when |
|---|---|---|---|
| Freeze | `0.11.0`, `0.12.0` | now | Phase 1 done |
| Beta | `1.0.0b1`, `b2`, … | hardening done | no open P0/P1, matrix passed, docs complete |
| Release candidate | `1.0.0rc1`, `rc2`, … | beta exit met | two quiet weeks with no change |
| Final | `1.0.0` | the last rc, unchanged | — |

- **Versions** follow PEP 440, and pacman sorts them the same way
  (`1.0.0b1 < 1.0.0b10 < 1.0.0rc1 < 1.0.0`).
- **Bump** the version in `pyproject.toml` *and* in the source fallback in
  `probolos/__init__.py`.
- **Tag** each release with a signed tag (`git tag -s`), on a commit of
  `main`: `release.yml` refuses any other.
- **`0.12.0`** is a release inside the freeze, not a new stage: the fixes
  from the 2026-10-04 security audit (Phase 1.6), no features. The beta still
  waits for the Phase 1 exit below.

---

## 3. Step guide

**M** = must, **S** = should, **C** = could.

### Phase 0: freeze (this week)

- [x] **0.1 M** Write the `Unreleased` part of `CHANGELOG.md`, covering:
  - gate-side "always" (T1);
  - holding devices with no agent, and notices (T2–T4);
  - the CI workflows;
  - the QA tooling;
  - every fix from the reviews.
  Release it as `0.11.0`.
- [x] **0.2 M** Add a "Feature freeze" note to the top of `CAPABILITIES.md`,
  and move the §1.2 items into its §3.
- [x] **0.3 M** Tag `v0.11.0`: the feature-complete snapshot the thesis
  describes.
- [ ] **0.4 S** Set up GitHub:
  - labels: `bug`, `security`, `qa`, `docs`, `packaging`, `release`,
    `post-1.0`;
  - milestones: `1.0.0b1`, `1.0.0rc1`, `1.0.0`;
  - private vulnerability reporting, plus secret scanning with push
    protection;
  - two issue templates. The bug report asks for the distro, kernel,
    Probolos version (release or `git describe`), desktop and
    `journalctl -u probolos` output. The security one points to private
    reporting.
- [ ] **0.5 M** Open one issue for every item in Phase 1.

### Phase 1: hardening → `1.0.0b1`

- [x] **1.1 M** Test the gate's refusal paths. Write tests for the `OSError`
  and refusal branches of `gate_server.py`, and the fork/drop/wait error paths
  of `privsep.py` (68% today) and `gate_client.py` (71%). Target: the coverage
  "boundary" (the root-side code plus its protocol, measured by
  `coverage.yml`) at ≥ 90%, up from 80%. Raise the floor in `coverage.yml` as
  it climbs.
- [x] **1.2 M** Remove the dead code. `AgentLink.notify_critical` has no
  caller, and the agent's `MSG_CRITICAL` handler still says "Use the
  terminal", which stopped being true when CRITICAL devices became approvable
  with the countdown. Remove the path, or make it true.
- [x] **1.3 M** Bring `SECURITY.md` up to date. Add the threat model for:
  - the gate-side trust write (`REQ_TRUST`): only the gate can write; only a
    device it admitted; only a fingerprint it measured; persistence is all
    a compromised analyzer gains;
  - the hold semantics: with no agent the device is held; the re-ask cap; a
    replayed "add" is ignored;
  - the `textsafe` cut fix;
  - dialog exit codes that are no decision.
- [ ] **1.4 M** Before every beta, run the deep property tests:
  `HYPOTHESIS_PROFILE=deep`. They must be clean.
- [ ] **1.5 S** Run an end-to-end test on a real kernel: a QEMU VM with
  `dummy_hcd` and `raw_gadget`, using `testbed/`, so a fake keyboard and a
  fake USB stick meet the real service. A scripted manual run before each
  beta is enough; a CI job is optional.
- [x] **1.6 S** Do a review pass over everything since `0.10.0`, root-side code
  first. Log every finding (§6). Done 2026-10-04 (`docs/QA-LOG.md`, "review
  (security audit)"); fixed in 0.12.0 except 1.11 to 1.13.
- [x] **1.11 M** The shared `nobody` account must not be able to open the
  gate. Any process running as `nobody` can kill the analyzer, and the gate
  reopens every hub on any analyzer exit (`SECURITY.md`, "Known
  weaknesses"). Run the analyzer as a dedicated account in the shipped unit
  and `install.sh`, and/or keep the hubs closed when the analyzer dies rather
  than exits. P1. Done in 0.13.0: the unit runs `--privsep-user probolos`
  (`systemd/probolos.sysusers`, created by `install.sh`); keeping the hubs
  closed was not taken (`SECURITY.md` says why).
- [ ] **1.12 S** Reap the analyzer's whole process tree: a subreaper in the
  gate, so nothing the analyzer forked outlives it on a terminal run. P1.
- [ ] **1.13 S** The agent socket: a directory the analyzer cannot write, or
  the agent checking `SO_PEERCRED` of the server, so another `nobody`
  process cannot take its place. P2. The service is covered by 1.11 (the
  directory's owner is `probolos`, which nothing else runs as); a run by hand
  as `nobody` is not.
- [x] **1.7 S** Leave hardware- and GUI-only modules out of coverage
  (`interrogate.py`, `countdown_dialog.py`), with the reason written next to
  the setting, then re-baseline both floors.
- [ ] **1.8 S** Package (T6): finish the parked `PKGBUILD`, then build,
  install and uninstall it cleanly on Manjaro.
- [x] **1.9 S** Add a release workflow. On a `v*` tag it should:
  - build the sdist and wheel;
  - write `SHA256SUMS`;
  - add a build-provenance attestation;
  - create a **draft** pre-release, which you publish yourself.
- [x] **1.10 C** Run mypy on the root-side modules.

**Exit:** every M item done, and every S item done or consciously moved. CI is
green. Then bump to `1.0.0b1`, update the changelog, tag it, and publish a
pre-release.

### Phase 2: beta (`1.0.0b1`, `b2`, …)

- [ ] **2.1 M** Use it yourself. Run the service daily on your own machine
  for at least four weeks, and open an issue for every surprise.
- [ ] **2.2 M** Run the hardware matrix (T9) and record the results in a
  new `TESTING.md`.
  - **Desktops:** KDE on Wayland and on X11, and a GNOME/zenity desktop; each
    with and without tk.
  - **Devices:** USB stick, keyboard, mouse, phone (MTP and tethering), hub,
    card reader.
  - **Flows:** install; plug; allow; refuse; a refused device getting the
    countdown; two copies refused; `--remove-all`; reboot; plugging in at the
    login screen; uninstall.
- [ ] **2.3 M** Write the docs (T10):
  - `README.md` and `systemd/README.md`, ordered for the service user
    (install → plug → answer);
  - screenshots of the three prompt levels.
- [ ] **2.4 M** Take the thesis measurements (`CAPABILITIES.md` §3.1), scripted
  and repeatable:
  - keystrokes that escape before the grab (procedure:
    `testbed/hidexp/EXPERIMENT.md`);
  - detection and miss rates;
  - false positives on ordinary devices;
  - how long each stage takes;
  - recovery after failures.
- [ ] **2.5 S** When fixes pile up, cut the next beta (`b2`, `b3`, …).

**Exit:** no open P0/P1; the matrix passed on at least two desktops; the docs
are complete.

### Phase 3: release candidate (`1.0.0rc1`)

- [ ] **3.1 M** The docs freeze as well. Only P0 and security fixes go in, and
  each one means a new rc.
- [ ] **3.2 M** Final checks:
  - the deep property run;
  - coverage floors;
  - actionlint and zizmor;
  - a five-flow hardware smoke test;
  - a fresh package install on a clean VM.
- [ ] **3.3 M** Two weeks with no change at all.

### Phase 4: `1.0.0`

- [ ] **4.1 M** The final release is the last rc plus the version number:
  - set the changelog date;
  - signed tag;
  - a GitHub release (not a pre-release);
  - the AUR package, if 1.8 was done.
- [ ] **4.2 S** Archive it for citation. Save the repository in Software
  Heritage, and mint a Zenodo DOI for the release; cite that DOI in the
  thesis.
- [ ] **4.3 C** After 1.0: new features go to `main` for 1.1. Create a
  `maint/1.0` branch only if 1.0 needs fixes while 1.1 is in progress.

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

- [ ] An issue with a label and milestone. Security issues go through a
      private advisory first.
- [ ] A regression test that fails before the fix and passes after it.
- [ ] `python -m tests.run_all` and `ruff check .` pass locally, and CI is
      green, coverage floors included.
- [ ] A line in `CHANGELOG.md` under `Unreleased`, in Fixed, Security or QA.
- [ ] The docs corrected, if the bug was in what they promised.

Rules for an LLM agent working on this repo:

1. No commits, tags, pushes or releases unless asked for that exact action.
2. Hand over changed files as an archive.
3. `python -m tests.run_all` and `ruff check .` pass before handover.
4. **No features.** Anything that is not a fix goes to `post-1.0`.

---

## 6. The thesis evidence

Keep a new `docs/QA-LOG.md`, one row per defect found:

| Date | What | How it was found | Severity | Fix commit |
|---|---|---|---|---|
| 2026-10-03 | `textsafe` cut skipped an escape and kept appending (`'\x1f0'` at limit 1 came out as `0...`) | property test, unaided | P2 | `ecb6453` |

"How it was found" is review, property test, hardware matrix, dogfooding or a
user report. Together with the coverage table (module → tests → coverage) and
the matrix in `TESTING.md`, that log is the evaluation chapter's data: what
each method found, on a system that did not change underneath the
measurement.
