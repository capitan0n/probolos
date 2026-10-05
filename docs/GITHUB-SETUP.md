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

## Repository settings (Settings → Advanced Security)

Applied on 2026-10-03:

- **Private vulnerability reporting:** on. `SECURITY.md` and
  `.github/ISSUE_TEMPLATE/config.yml` link to it.
- **Secret Protection**, with **Push protection:** on.
- **Dependency graph**, **Dependabot alerts** and **Dependabot security
  updates:** on. Version updates come from `.github/dependabot.yml`.
- **CodeQL analysis:** default setup. Its first two alerts were triaged as
  false positives (`docs/QA-LOG.md`, static analysis).

Issue templates are in `.github/ISSUE_TEMPLATE/`: the bug report form, and the
security contact link that points to private reporting. Blank issues are off.

## Release protection

Not applied yet; the workflow alone cannot enforce these. Read on
2026-10-05 from the repository: two branch rulesets, `protect-main` (no
deletion, no force push, no bypass) and `main-checks` (required checks
`test (3.10)`, `test (3.12)`, `test (3.14)`, `root`; Repository admin may
bypass "always"; no pull-request rule). No tag ruleset, so anyone with write
access can create, move or delete a `v*` tag. `release.yml` refuses a tag on
a commit that is not on `main` and runs the checks first, but it cannot stop
the tag itself.

**1. Tag ruleset** (Settings → Rules → Rulesets → New ruleset → New tag
ruleset). Name `release-tags`, enforcement **Active**. Bypass list:
Repository admin, **Always allow**. Target tags: include by pattern `v*`.
Rules: **Restrict creations**, **Restrict updates**, **Restrict deletions**,
**Block force pushes**. Only the maintainer can then create or move a
release tag. A ruleset cannot require a *signed tag*: "Require signed
commits" checks commits, and a tag on a commit already on `main` brings none.
Sign by habit (`git tag -s`, then `git tag -v`); GitHub shows "Verified" on
the tag when the key is on the account.

**2. Required checks** (Rulesets → `main-checks` → Require status checks to
pass → add checks, source GitHub Actions). Add `build` (the wheel holds the
package alone, the suite runs from the sdist), `coverage` and `typecheck`.
Do not add `lint`, `shellcheck` or `units`: their workflows filter on paths,
so a pull request that does not touch those paths never gets the check and
waits forever. A required job that is renamed or turned into a matrix gets a
new check name, and the ruleset then waits for one that never reports.

**3. Pull requests, for one maintainer.** An author cannot approve their own
pull request, so required approvals of 1 or more lock a solo maintainer out
unless they bypass, and a bypass skips every rule in its ruleset, the
required checks included. Recommended: in `main-checks` tick **Require a
pull request before merging** with **Required approvals 0**, and remove the
admin bypass. Every change, Dependabot's too, then reaches `main` through a
pull request with green checks; an admin can still edit or disable a
ruleset in an emergency. Keep `protect-main` as it is.

**4. Immutable releases** (Settings → General → Releases → Enable release
immutability), before the next tag. Publishing then locks the tag to its
commit and the assets to their bytes; the notes and the pre-release/latest
flags stay editable. A deleted immutable release frees the tag but not the
name: a bad published asset means a new patch version. Drafts stay mutable,
which is how `release.yml` works (draft, check, publish).

**5. Actions** (Settings → Actions → General): allow only actions created by
GitHub and tick **Require actions to be pinned to a full-length commit
SHA**. Every `uses:` in `.github/workflows/` is an `actions/*` action pinned
to a SHA today, and Dependabot keeps the pins current.

**6. Check what could not be read from here**: Settings → Advanced Security
(Secret Protection with push protection, Dependabot alerts and security
updates, CodeQL default setup), recorded above as applied on 2026-10-03.
Private vulnerability reporting was confirmed on.

Later, optional: a `release` environment (Settings → Environments; tag
pattern `v*`; required reviewer the maintainer, "Prevent self-review" off)
named in `release.yml`'s build and draft jobs, so nothing is attested or
drafted without a click.

## Archiving the 1.0.0 release (ROADMAP 4.2)

- **Zenodo:** sign in at zenodo.org with GitHub and switch this repository on
  under GitHub integration, before publishing the 1.0.0 release; publishing
  it then mints the DOI. Zenodo takes the metadata from `CITATION.cff`.
- **Software Heritage:** request an archive of the repository at
  archive.softwareheritage.org ("Save code now") after the release.

## Phase 1 issues (ROADMAP 0.5)

One per item, milestone `1.0.0b1`. Titles and labels ready to paste. Mark an
item as done in the issue when its change lands.

| # | Title | Labels | State |
|---|---|---|---|
| 1.1 | Test the gate's refusal paths; boundary coverage ≥ 90% | `qa` | Done: `tests/test_boundary.py`, boundary 95%, floors 93/83 |
| 1.2 | `MSG_CRITICAL` says "Use the terminal" and `notify_critical` has no caller | `bug` | Done: made true (critical-urgency "still blocked" notice) |
| 1.3 | SECURITY.md: threat model for REQ_TRUST, holding, the textsafe cut, dialog exit codes | `docs`, `security` | Done |
| 1.4 | Deep property run before each beta (`HYPOTHESIS_PROFILE=deep`) | `qa` | Clean on `aa2a0d3` (QA-LOG); repeat on the commit tagged b1 |
| 1.5 | End-to-end run on a real kernel: QEMU + `dummy_hcd`/`raw_gadget` | `qa` | Open |
| 1.6 | Review pass over everything since 0.10.0, root side first | `qa`, `security` | Open; log findings in `docs/QA-LOG.md` |
| 1.7 | Leave hardware/GUI-only modules out of coverage; re-baseline | `qa` | Done |
| 1.8 | Finish the PKGBUILD; build, install, uninstall cleanly on Manjaro | `packaging` | Open |
| 1.9 | Release workflow: sdist + wheel, SHA256SUMS, provenance, draft pre-release | `release` | Done: `.github/workflows/release.yml` |
| 1.10 | mypy on the root-side modules | `qa` | Done: `mypy.yml`, config in `pyproject.toml` |
