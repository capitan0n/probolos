# GitHub and PyPI setup

One-time settings for the road to 1.0.0 (ROADMAP 0.4, 0.5 and 1.14), applied
by hand in the repository settings and on PyPI. Nothing here changes code.

## Labels and milestones

| Label | Colour | Meaning |
|---|---|---|
| `bug` | `#d73a4a` | documented behaviour is not what happens |
| `security` | `#b60205` | a security fix; private advisory first |
| `qa` | `#0e8a16` | tests, CI, linters, coverage |
| `docs` | `#0075ca` | documentation |
| `packaging` | `#5319e7` | PKGBUILD, wheel, install.sh |
| `release` | `#fbca04` | release engineering |
| `post-1.0` | `#cfd3d7` | a feature, or anything in doubt: not before 1.0.0 |

Priority labels `P0` to `P3` are optional (ROADMAP §4).

Milestones: `1.0.0b1` (Phase 1), `1.0.0rc1` (Phase 2), `1.0.0` (Phases 3 and
4). ROADMAP 0.5: one issue per Phase 1 item, milestone `1.0.0b1`.

## Repository security (applied 2026-10-03)

- **Private vulnerability reporting:** on; `SECURITY.md` and
  `.github/ISSUE_TEMPLATE/config.yml` link to it.
- **Secret Protection** with **push protection:** on.
- **Dependency graph, Dependabot alerts and security updates:** on; version
  updates come from `.github/dependabot.yml`.
- **CodeQL:** default setup; its first two alerts were false positives
  (`docs/QA-LOG.md`, "Static analysis").
- Issue templates are in `.github/ISSUE_TEMPLATE/`; blank issues are off.

## Release protection (not applied yet)

As read on 2026-10-05: two branch rulesets, `protect-main` (no deletion, no
force push, no bypass) and `main-checks` (required checks `test (3.10)`,
`test (3.12)`, `test (3.14)` and `root`; admins may always bypass; no
pull-request rule). There is no tag ruleset, so anyone with write access can
create, move or delete a `v*` tag; `release.yml` refuses a tag that is not on
`main`, but cannot stop the tag itself.

1. **Tag ruleset** (Settings → Rules → Rulesets → New tag ruleset): name
   `release-tags`, enforcement Active, bypass Repository admin (always),
   target `v*`, rules Restrict creations, Restrict updates, Restrict deletions
   and Block force pushes. A ruleset cannot require a *signed* tag: sign by
   habit (`git tag -s`, check with `git tag -v`).
2. **Required checks** in `main-checks`: add `build`, `coverage` and
   `typecheck`. Not `lint`, `shellcheck` or `units`: their workflows filter on
   paths, so a pull request outside those paths never gets the check and waits
   forever. Renaming a required job also leaves the ruleset waiting.
3. **Pull requests, for one maintainer:** in `main-checks`, require a pull
   request with **0** required approvals and remove the admin bypass. (An
   author cannot approve their own pull request, and a bypass skips the
   required checks too.) Keep `protect-main` as it is.
4. **Immutable releases** (Settings → General → Releases): publishing locks a
   release's tag and assets. Drafts stay editable, which is how `release.yml`
   works (draft, check, publish).
5. **Actions** (Settings → Actions → General): allow actions created by
   GitHub plus `pypa/gh-action-pypi-publish@*`, and require actions to be
   pinned to a full-length commit SHA. Dependabot keeps the pins current.

Optional later: a `release` environment (tags `v*`, the maintainer as required
reviewer) named in `release.yml`'s build and draft jobs, so nothing is attested
or drafted without a click.

## Publishing to PyPI (ROADMAP 1.14)

`release.yml` uploads each tag's sdist and wheel to TestPyPI as soon as they
are built, and to PyPI once the maintainer approves. Both use trusted
publishing: there is no API token to create, store or leak. Set up once,
before the first tag that should reach PyPI:

1. **Accounts** on pypi.org and on test.pypi.org (two separate sites), each
   with two-factor authentication.
2. **Pending publishers.** On each site, Your account → Publishing, add a
   GitHub publisher:

   | Field | pypi.org | test.pypi.org |
   |---|---|---|
   | PyPI Project Name | `probolos` | `probolos` |
   | Owner | `capitan0n` | `capitan0n` |
   | Repository name | `probolos` | `probolos` |
   | Workflow name | `release.yml` | `release.yml` |
   | Environment name | `pypi` | `testpypi` |

   A pending publisher does not reserve the name; the first upload does.
3. **Environments** (Settings → Environments): `testpypi` and `pypi`, each
   limited to tags matching `v*`. `pypi` also gets the maintainer as required
   reviewer, with "Prevent self-review" off.
4. **Allowed actions:** see step 5 of "Release protection".

**Each release:** tag → checks → build → draft release and TestPyPI upload →
the `pypi` job waits for approval (Actions → the run → Review deployments).
Before approving, look at <https://test.pypi.org/project/probolos/> and check
that TestPyPI serves the file the draft holds:

```bash
pip download --no-deps --index-url https://test.pypi.org/simple/ \
    --dest /tmp/probolos-check "probolos==1.0.0b1"
sha256sum /tmp/probolos-check/*   # the same line as in the draft's SHA256SUMS
```

Then approve, and publish the draft once PyPI has the files. Nothing on PyPI
can be replaced: a bad upload means a new version (`1.0.0b2`).

## Archiving 1.0.0 (ROADMAP 4.2)

- **Zenodo:** switch this repository on in Zenodo's GitHub integration
  *before* publishing 1.0.0; publishing then mints the DOI, with the metadata
  from `CITATION.cff`.
- **Software Heritage:** "Save code now" at archive.softwareheritage.org after
  the release.
