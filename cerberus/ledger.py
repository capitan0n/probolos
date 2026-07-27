"""
The descriptor ledger: identity across time, not just at one moment.

Every check in stages 1-3 judges a single connection in isolation. That misses
the attack that is interesting precisely because it is spread out: a device
that behaves as an innocent flash drive for three days and then reappears with
an added keyboard interface.

If descriptors are TESTIMONY -- the framing the whole project rests on -- then
a contradiction with the same device's earlier testimony is the strongest
signal available. It is cross-examination. A device can lie, but it has to keep
the same lie, and the ledger is what remembers.

WHY HASH THE RAW BYTES
----------------------
The fingerprint is a hash of the unmodified descriptor blob, not of our parsed
view of it. Hashing the parsed view would ignore any field the parser does not
model -- which is exactly where a device wanting to change quietly would put
the change.

WHY IDENTITY IS NOT THE SERIAL NUMBER
-------------------------------------
Field data from real hardware: a Realtek Bluetooth radio reports serial
00e04c000001, a factory placeholder built from Realtek's OUI and shared across
countless units; a Chicony camera reports 0001. Serial numbers are not unique
and are trivially forged. So the ledger keys on vendor:product:serial as a
CLAIM, and treats a matching claim with a different descriptor hash as the
finding -- rather than trusting the serial to identify anything.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

def default_path() -> Path:
    """
    Where the ledger lives.

    Under root (systemd service) this is /var/lib/cerberus. Run by hand as a
    normal user it is the XDG state dir, so a --dry-run or a --list never trips
    over a permission error on a directory only root can write. Falling back to
    a writable location is not laziness: a history file the user cannot write
    is the same as no history, and it should fail that way quietly rather than
    erroring on every device.
    """
    import os
    if os.geteuid() == 0:
        return Path("/var/lib/cerberus/ledger.json")
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "cerberus" / "ledger.json"


DEFAULT_PATH = default_path()

SCHEMA_VERSION = 1


@dataclass
class Entry:
    """Everything the ledger remembers about one claimed identity."""
    identity: str
    descriptor_hash: str
    first_seen: float
    last_seen: float
    times_seen: int = 1
    ports: List[str] = field(default_factory=list)
    decisions: List[str] = field(default_factory=list)
    # Every distinct descriptor hash ever presented under this identity. The
    # list itself is the evidence of drift; length > 1 means the device has
    # changed what it says it is.
    known_hashes: List[str] = field(default_factory=list)


def descriptor_fingerprint(dev) -> Optional[str]:
    """SHA-256 of the device's raw descriptor blob."""
    raw = getattr(dev, "raw_descriptors", None)
    if not raw:
        return None
    return hashlib.sha256(raw).hexdigest()


def identity_of(dev) -> str:
    """
    The identity a device CLAIMS. Not proof of anything; just what it said.

    Serial is included when present because a change of descriptors under a
    constant serial is the interesting case. When absent, vendor:product alone
    will collide between identical units, which is why a first sighting is
    never treated as suspicious.
    """
    serial = getattr(dev, "serial", None) or "-"
    return f"{dev.vendor_id}:{dev.product_id}:{serial}"


class Ledger:
    """A small JSON store. Deliberately not a database."""

    def __init__(self, path: Path = DEFAULT_PATH):
        self.path = Path(path)
        self.entries: Dict[str, Entry] = {}
        self.load_error: Optional[str] = None
        self.load()

    # ---------- persistence ----------

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            # A corrupt ledger must not stop the gate from working. Losing
            # history is an inconvenience; refusing to admit a keyboard because
            # a JSON file is malformed is a lockout.
            self.load_error = f"{exc}"
            return
        if data.get("schema") != SCHEMA_VERSION:
            self.load_error = f"unsupported ledger schema {data.get('schema')}"
            return
        for key, raw in (data.get("entries") or {}).items():
            self.entries[key] = Entry(**raw)

    def save(self) -> Optional[str]:
        """Write atomically. Returns an error string, or None on success."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            payload = {
                "schema": SCHEMA_VERSION,
                "entries": {k: asdict(v) for k, v in self.entries.items()},
            }
            tmp.write_text(json.dumps(payload, indent=1))
            # Rename is atomic on the same filesystem: a crash mid-write leaves
            # the previous ledger intact rather than a truncated file.
            tmp.replace(self.path)
            return None
        except OSError as exc:
            return str(exc)

    # ---------- use ----------

    def lookup(self, dev) -> Optional[Entry]:
        return self.entries.get(identity_of(dev))

    def record(self, dev, decision: str) -> None:
        """Add or update this device's history. Call after every decision."""
        key = identity_of(dev)
        digest = descriptor_fingerprint(dev) or "-"
        now = time.time()
        entry = self.entries.get(key)

        if entry is None:
            self.entries[key] = Entry(
                identity=key, descriptor_hash=digest,
                first_seen=now, last_seen=now,
                ports=[dev.name], decisions=[decision],
                known_hashes=[digest],
            )
            return

        entry.last_seen = now
        entry.times_seen += 1
        entry.descriptor_hash = digest
        if digest not in entry.known_hashes:
            entry.known_hashes.append(digest)
        if dev.name not in entry.ports:
            entry.ports.append(dev.name)
        entry.decisions.append(decision)
        # Keep the tail only. An audit trail belongs in the JSONL log; this
        # file exists to answer "has this changed?", and unbounded growth in a
        # file read at every device attachment is a real operational problem.
        entry.decisions = entry.decisions[-20:]
