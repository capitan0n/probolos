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
"""

from __future__ import annotations

import json
import os
from pathlib import Path


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
    tmp = path.with_suffix(".tmp")

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
