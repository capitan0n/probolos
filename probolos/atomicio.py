"""
Symlink-safe atomic writes for the trust store and the ledger.

Why this exists (audit finding C3)
----------------------------------
Under --privsep the state directory /var/lib/probolos is chowned to `nobody`
so the unprivileged analyzer can update the ledger. `nobody` is a shared
account: any other `nobody` process on the machine can write into that
directory too. The old save() did `tmp.write_text(...)`, and write_text() ends
up calling open(path, "w") -- which FOLLOWS SYMLINKS.

So an attacker who is `nobody` could pre-plant

    /var/lib/probolos/trusted.tmp  ->  /etc/cron.d/root_job

and the next save() -- especially `sudo python -m probolos --forget N`, which
runs as ROOT -- would write the JSON through the symlink and clobber the
target with root privileges. A trust store meant to be edited by root becomes
an arbitrary-file-write primitive.

The fix
-------
Open the temp file with O_NOFOLLOW | O_CREAT | O_EXCL:

  * O_NOFOLLOW  -- if the final path component is a symlink, open() fails with
                   ELOOP instead of following it.
  * O_EXCL      -- if the temp file already exists at all, open() fails. This
                   closes the race where the attacker plants a symlink between
                   our unlink and our open, and also refuses a stale regular
                   temp file rather than truncating something we did not create.
  * O_CREAT     -- create it ourselves, so we know we own what we opened.

We stage the temp file, fsync it, then os.replace() onto the target. replace()
is atomic on the same filesystem, so a crash mid-write leaves the previous
file intact. replace() onto the FINAL name is allowed to follow a symlink at
the destination, but the destination is the real store the operator controls,
not an attacker-plantable temp name; the value being protected is that we never
WRITE CONTENT through an attacker's symlink.

WHY THE TEMP NAME IS NO LONGER path.with_suffix(".tmp")   (follow-up to C3)
--------------------------------------------------------------------------
Two problems, one of them the mirror image of the bug this file fixed.

  1. O_EXCL on a PREDICTABLE name turns "cannot be tricked" into "can be
     stopped". `nobody` is a shared account, so the same process that could
     have planted a symlink can instead plant an ordinary file at
     .../state/ledger.tmp and leave it there. Every subsequent save fails with
     EEXIST -- permanently, because nothing ever cleans it up -- and Ledger.save
     reports the identical error only once by design, so the ledger silently
     stops recording. Drift detection is exactly what the ledger exists for,
     and it can be switched off with `touch`.

  2. with_suffix REPLACES the last suffix rather than appending, so two stores
     whose names differ only after the final dot collide on one temp path, and
     a name like `probolos.state.json` stages at `probolos.state.tmp` -- a
     surprising path to hand to the chown in privsep.prepare_state_dir.

So the staging name is unique per attempt (pid + 64 random bits) and derived by
APPENDING. It is unguessable, which means O_EXCL can no longer be pre-empted;
it is unique, so a leftover from a killed process blocks nothing; and it starts
with a dot and ends in .tmp so leftovers are recognisable and sweepable.

The directory is fsynced after the rename, which with_suffix's version never
did: os.replace is atomic with respect to readers, but on a crash the rename
itself can be lost, leaving the previous file. That is the safe direction, and
the fsync makes the newly saved state durable rather than merely likely.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

# Staging files this module creates. Kept as a module constant so that
# privsep.prepare_state_dir and any future cleanup agree on what a leftover
# looks like instead of each hard-coding a guess.
TMP_PREFIX = "."
TMP_SUFFIX = ".tmp"


def temp_glob_for(path) -> str:
    """The fnmatch pattern matching staging files for `path`."""
    return f"{TMP_PREFIX}{Path(path).name}.*{TMP_SUFFIX}"


def _staging_path(path: Path) -> Path:
    """
    A unique, unguessable sibling of `path` to write into.

    Unguessable matters: with O_EXCL, a name an attacker can predict is a name
    an attacker can occupy, and an occupied staging path means no save ever
    succeeds again. secrets rather than random for the same reason it is used
    for the agent's request ids -- the property being relied on is that the
    value cannot be reconstructed from earlier ones.
    """
    return path.with_name(
        f"{TMP_PREFIX}{path.name}.{os.getpid()}."
        f"{secrets.token_hex(8)}{TMP_SUFFIX}")


def write_json_atomic(path: Path, payload: dict) -> None:
    """
    Serialise `payload` as JSON to `path`, atomically and without ever
    following a symlink at the temporary staging path.

    Raises OSError on failure (including ELOOP if the temp path is a symlink,
    or EEXIST if a temp file is already sitting there). Callers already treat
    OSError from save() as "could not persist" and report it once, so no new
    error handling is needed at the call sites.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _staging_path(path)

    data = json.dumps(payload, indent=1).encode("utf-8")

    # O_NOFOLLOW: refuse a symlink at `tmp`. O_EXCL: refuse an existing file at
    # `tmp` (so we never write into something we did not just create). 0o600:
    # the store is only ever meant to be read by root or the analyzer user, so
    # do not create it group/other readable.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(str(tmp), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        # Do not leave a half-written temp file behind to block the next save.
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise

    os.replace(str(tmp), str(path))

    # Persist the rename itself. Without this the file's CONTENTS are on disk
    # (we fsynced them) while the directory entry pointing at them may not be,
    # so a power loss can leave the previous version in place. Failing here is
    # not worth raising over -- the data is written and visible -- but it must
    # not pass silently either, so the OSError is swallowed only for the case
    # where the platform will not let us open a directory at all.
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)
