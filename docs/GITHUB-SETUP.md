# GitHub setup for the road to 1.0.0

ROADMAP 0.4 and 0.5, written out to be applied by hand in the repository
settings. Nothing here changes code.

## Labels (Issues → Labels)

| Label | Colour | Meaning |
|---|---|---|
| `bug` | `#d73a4a` | Documented behaviour is not what happens |
| `security` | `#b60205` | A security fix; goes through a private advisory first |
| `qa` | `#0e8a16` | Tests, CI, linters, coverage |
| `docs` | `#0075ca` | Documentation |
| `packaging` | `#5319e7` | PKGBUILD, wheel, install.sh |
| `release` | `#fbca04` | Release engineering |
| `post-1.0` | `#cfd3d7` | A feature, or anything in doubt: not before 1.0.0 |

Priority, if you want it as labels too: `P0`, `P1`, `P2`, `P3` (ROADMAP §4).

## Milestones (Issues → Milestones)

- `1.0.0b1`: Phase 1, hardening.
- `1.0.0rc1`: Phase 2 exit, beta.
- `1.0.0`: Phases 3 and 4.

## Repository settings

- **Settings → Code security → Private vulnerability reporting:** enable.
  `SECURITY.md` and `.github/ISSUE_TEMPLATE/config.yml` already link to it.
- **Settings → Code security → Secret scanning:** enable, with **Push
  protection**.
- Issue templates are in `.github/ISSUE_TEMPLATE/`: the bug report form, and
  the security contact link that points to private reporting. Blank issues
  are off.

## Phase 1 issues (ROADMAP 0.5)

One per item, milestone `1.0.0b1`. Titles and labels ready to paste. Mark an
item as done in the issue when its change lands.

| # | Title | Labels | State in this tree |
|---|---|---|---|
| 1.1 | Test the gate's refusal paths; boundary coverage ≥ 90% | `qa` | Done: `tests/test_boundary.py`, boundary 95%, floors 93/83 |
| 1.2 | `MSG_CRITICAL` says "Use the terminal" and `notify_critical` has no caller | `bug` | Done: made true (critical-urgency "still blocked" notice) |
| 1.3 | SECURITY.md: threat model for REQ_TRUST, holding, the textsafe cut, dialog exit codes | `docs`, `security` | Done |
| 1.4 | Deep property run before each beta (`HYPOTHESIS_PROFILE=deep`) | `qa` | Clean on this tree (QA-LOG); repeat on the commit tagged b1 |
| 1.5 | End-to-end run on a real kernel: QEMU + `dummy_hcd`/`raw_gadget` | `qa` | Open |
| 1.6 | Review pass over everything since 0.10.0, root side first | `qa`, `security` | Open; log findings in `docs/QA-LOG.md` |
| 1.7 | Leave hardware/GUI-only modules out of coverage; re-baseline | `qa` | Done |
| 1.8 | Finish the PKGBUILD; build, install, uninstall cleanly on Manjaro | `packaging` | Open |
| 1.9 | Release workflow: sdist + wheel, SHA256SUMS, provenance, draft pre-release | `release` | Done: `.github/workflows/release.yml` |
| 1.10 | mypy on the root-side modules | `qa` | Done: `mypy.yml`, config in `pyproject.toml` |
