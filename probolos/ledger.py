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
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Dict, List, Optional

from . import atomicio

def default_path() -> Path:
    """
    Where the ledger lives.

    Under root (systemd service) this is /var/lib/probolos/state/. Run by hand
    as a normal user it is the XDG state dir, so a --dry-run or a --list never
    trips over a permission error on a directory only root can write. Falling
    back to a writable location is not laziness: a history file the user cannot
    write is the same as no history, and it should fail that way quietly rather
    than erroring on every device.

    WHY THE `state/` SUBDIRECTORY (audit finding C3)
    ------------------------------------------------
    Under --privsep the analyzer runs as `nobody` and must be able to write the
    ledger, so its directory is chowned to that account. Directory write
    permission is stronger than it looks: it allows unlinking and replacing ANY
    file in that directory, whatever the file's own owner and mode. So while
    the ledger and the trust store shared one directory, handing it to `nobody`
    also handed over the trust store -- and a hostile process running as the
    same shared account could drop in an entry that admits its own BadUSB
    without a prompt.

    Separating them fixes that structurally rather than by permissions alone:
    only `state/` is handed over. /var/lib/probolos/ itself, which holds
    trusted.json, stays root-owned, so the analyzer can read trust but can
    neither rewrite nor replace it.
    """
    import os
    if os.geteuid() == 0:
        return Path("/var/lib/probolos/state/ledger.json")
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "probolos" / "ledger.json"


DEFAULT_PATH = default_path()

SCHEMA_VERSION = 1

# Per-entry list bounds. The ledger is read AND rewritten on every device
# attachment, so anything that grows once per attachment grows a file that is
# on the hot path -- and every one of these lists is fed by values the device
# chooses. Generous enough that no honest device ever reaches them.
MAX_DECISIONS = 20
MAX_KNOWN_HASHES = 32     # 32 distinct descriptor sets is already an alarm
MAX_PORTS = 32            # more ports than any machine has


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

    @classmethod
    def from_raw(cls, raw) -> Optional["Entry"]:
        """
        Build an Entry from untrusted JSON, or return None if it is not one.

        WHY THIS EXISTS
        ---------------
        `Entry(**raw)` treats the file's contents as state. They are input. The
        ledger is written by the unprivileged half and lives on disk, so its
        shape is whatever was last written there -- and one unexpected key, one
        missing key or one null value raises TypeError out of __init__, from
        inside load(), from inside Ledger.__init__. Nothing catches it, the
        daemon never finishes starting, `authorized_default` is never set to 0,
        and the gate stays open. A file that cannot be trusted must not be able
        to decide whether the gate closes.

        Unknown keys are dropped rather than rejected, so a ledger written by a
        newer version degrades to what this version understands instead of
        being thrown away in full.
        """
        if not isinstance(raw, dict):
            return None

        def as_str(value) -> Optional[str]:
            return value if isinstance(value, str) else None

        def as_time(value) -> Optional[float]:
            # bool is a subclass of int in Python, so an explicit check is
            # needed: a JSON `true` is not a timestamp.
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return None
            return float(value)

        def as_str_list(value) -> List[str]:
            # Individual bad elements are dropped, not the whole list: a
            # truncated port history is still usable history.
            if not isinstance(value, list):
                return []
            return [item for item in value if isinstance(item, str)]

        identity = as_str(raw.get("identity"))
        digest = as_str(raw.get("descriptor_hash"))
        first_seen = as_time(raw.get("first_seen"))
        last_seen = as_time(raw.get("last_seen"))
        if identity is None or digest is None:
            return None
        if first_seen is None or last_seen is None:
            return None

        times_seen = raw.get("times_seen", 1)
        if isinstance(times_seen, bool) or not isinstance(times_seen, int):
            times_seen = 1

        return cls(
            identity=identity,
            descriptor_hash=digest,
            first_seen=first_seen,
            last_seen=last_seen,
            times_seen=max(1, times_seen),
            ports=as_str_list(raw.get("ports")),
            decisions=as_str_list(raw.get("decisions")),
            known_hashes=as_str_list(raw.get("known_hashes")),
        )


# from_raw() names every field of Entry explicitly. If a field is added to the
# dataclass and not to from_raw, a ledger that HAS that data would silently
# load it as the default -- history quietly lost rather than loudly refused.
# The test suite compares this set against what from_raw round-trips, so the
# two cannot drift apart unnoticed.
ENTRY_FIELD_NAMES = frozenset(f.name for f in fields(Entry))


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
        self._last_save_error: Optional[str] = None
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
        entries = data.get("entries")
        if entries is None:
            return
        if not isinstance(entries, dict):
            # `"entries": []` is valid JSON of the right schema version and
            # would raise AttributeError on .items(). Same class of problem as
            # the one below, same answer: no history rather than no gate.
            self.load_error = "ledger 'entries' is not an object"
            return

        skipped = 0
        for key, raw in entries.items():
            if not isinstance(key, str):
                skipped += 1
                continue
            entry = Entry.from_raw(raw)
            if entry is None:
                skipped += 1
                continue
            self.entries[key] = entry

        if skipped:
            # Loud on purpose. A dropped entry is a device whose history is
            # gone, so its next appearance looks like a first sighting and no
            # drift can be reported for it. Silently ignoring malformed entries
            # would turn a corrupt file into a way of ERASING the ledger's
            # memory of one chosen device -- which is precisely the attack the
            # ledger exists to catch.
            self.load_error = (
                f"{skipped} malformed ledger "
                f"{'entry' if skipped == 1 else 'entries'} ignored -- "
                f"drift detection for those devices is lost")

    def save(self) -> Optional[str]:
        """
        Write atomically. Returns an error string, or None on success.

        A repeated failure is reported only once: an unwritable ledger is a
        single condition, and printing it for every device attachment would
        bury the findings the user actually needs to read.
        """
        try:
            payload = {
                "schema": SCHEMA_VERSION,
                "entries": {k: asdict(v) for k, v in self.entries.items()},
            }
            # Symlink-safe atomic write: the state dir is nobody-owned under
            # --privsep, so the staging path must not be followable. See
            # atomicio for the full rationale.
            atomicio.write_json_atomic(self.path, payload)
            return None
        except OSError as exc:
            message = str(exc)
            if message == self._last_save_error:
                return None          # already reported; stay quiet
            self._last_save_error = message
            return message

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
        entry.decisions = entry.decisions[-MAX_DECISIONS:]
        # The same bound, for the same reason, on the two lists that had none.
        #
        # `decisions` was capped and these were not, which left the cap doing
        # nothing against the case that actually produces growth: a device
        # whose descriptors differ on every attachment appends a NEW hash every
        # time, under one identity, in a file that is parsed and rewritten on
        # every single device event. Sixty-four characters per plug-in, from a
        # device whose entire purpose may be to be plugged in repeatedly.
        #
        # Truncation is from the FRONT, keeping the newest -- except for the
        # first hash, which is deliberately preserved: it is the one the drift
        # rule compares against, and losing it would let a device wash its own
        # history out of the ledger simply by changing shape often enough.
        # That would turn a memory-growth annoyance into an erasure attack on
        # exactly the evidence this file exists to hold.
        if len(entry.known_hashes) > MAX_KNOWN_HASHES:
            entry.known_hashes = (entry.known_hashes[:1]
                                  + entry.known_hashes[-(MAX_KNOWN_HASHES - 1):])
        entry.ports = entry.ports[-MAX_PORTS:]
