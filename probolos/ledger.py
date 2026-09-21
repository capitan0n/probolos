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
import math
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
    # The descriptor set drift is measured AGAINST: the one first seen under
    # this identity, and thereafter only whatever a human has approved.
    #
    # `descriptor_hash` above cannot serve that purpose, and using it was the
    # bug: record() overwrites it on EVERY decision, so the act of recording a
    # refusal -- or of merely queueing a device while the screen was locked --
    # adopted the attacker's own blob as the reference, and the next appearance
    # of the very same device read as clean. The evidence survived in
    # known_hashes and no rule ever looked at it.
    baseline_hash: str = ""
    # Byte-for-byte hash of the last seen raw blob. Kept beside the normalized
    # fingerprint for forensics: it answers "did anything at all differ"
    # (bcdUSB, bMaxPower, endpoint companion descriptors -- all bus-negotiated
    # and none of them the drift alarm's business) without being the field the
    # CRITICAL rule fires on. The normalized fingerprint above is what the
    # alarm reads; this is only ever displayed.
    raw_hash: str = ""

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
            try:
                converted = float(value)
            except (ValueError, OverflowError):
                return None
            return converted if math.isfinite(converted) else None

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

        known = as_str_list(raw.get("known_hashes"))
        # Ledgers written before baseline_hash existed still carry the answer:
        # known_hashes[0] is the first set ever recorded, and record() below
        # deliberately preserves that element when it truncates. Migrating here
        # rather than refusing the entry means an existing history keeps its
        # drift detection instead of silently starting over -- which would be
        # the erasure this whole field exists to prevent, performed by the fix.
        #
        # ONE-TIME MIGRATION: entries filed under the raw-blob fingerprint (any
        # ledger written before descriptor_fingerprint became normalized) have
        # a baseline that CANNOT be matched by the new fingerprint, so every
        # replug of every remembered device reads as drift on the first run
        # after the upgrade. from_raw cannot recompute the correct baseline --
        # it does not have the device -- so the entry's baseline is CLEARED
        # here when the ledger predates the normalized fingerprint. record()
        # then re-baselines from the next actual sighting, and the alarm
        # returns for real changes on the second and later visits. Losing one
        # ledger's worth of "yes I have seen this before" is a smaller failure
        # than crying wolf on every device the day of the upgrade.
        # `fingerprint_scheme` is a file-level marker copied into each entry
        # by Ledger.load() so from_raw can decide alone whether the baseline
        # value stored under this entry can still be compared against a
        # freshly-computed fingerprint. Any value other than the current
        # scheme is treated as "unknown, cannot trust the stored baseline",
        # and the baseline is cleared so record() will re-learn from the next
        # sighting -- one visit of relearning beats crying wolf on every
        # remembered device the day of the upgrade.
        fingerprint_scheme = as_str(raw.get("fingerprint_scheme")) or "raw"
        baseline = as_str(raw.get("baseline_hash")) or ""
        if fingerprint_scheme != "normalized-v1":
            baseline = ""
        elif not baseline:
            baseline = known[0] if known else digest

        return cls(
            identity=identity,
            descriptor_hash=digest,
            first_seen=first_seen,
            last_seen=last_seen,
            times_seen=max(1, times_seen),
            ports=as_str_list(raw.get("ports")),
            decisions=as_str_list(raw.get("decisions")),
            known_hashes=known,
            baseline_hash=baseline,
            raw_hash=as_str(raw.get("raw_hash")) or "",
        )


# from_raw() names every field of Entry explicitly. If a field is added to the
# dataclass and not to from_raw, a ledger that HAS that data would silently
# load it as the default -- history quietly lost rather than loudly refused.
# The test suite compares this set against what from_raw round-trips, so the
# two cannot drift apart unnoticed.
ENTRY_FIELD_NAMES = frozenset(f.name for f in fields(Entry))


def descriptor_fingerprint(dev) -> Optional[str]:
    """
    SHA-256 of a NORMALIZED view of what the device claims to be.

    WHY NORMALIZED, WHEN THE FILE HEADER SAYS "hash the raw bytes"
    --------------------------------------------------------------
    Hashing the raw descriptor blob was measured, on real hardware, to produce
    a different digest for the same physical stick when plugged into a USB 2
    vs. a USB 3 controller: bcdUSB flips, bMaxPacketSize0 becomes 9 instead of
    64, bMaxPower switches to 8 mA units, and SuperSpeed endpoint companion
    descriptors appear. All of these are BUS-controller-dependent -- the device
    did not change what it is, the port did -- so a raw hash produced a
    CRITICAL drift alarm on every controller swap. That is a false positive
    reachable by moving the same Kingston stick from a back-panel USB2 port to
    a front-panel USB3 port. Once every user hits that once, the rule stops
    being read.

    So the fingerprint compared for drift is built from what the DEVICE says
    it is, not what the enumeration NEGOTIATED. It keeps:

        idVendor, idProduct, bcdDevice
          -- who made it and what firmware revision. Legitimate firmware
             updates are exactly the case the drift rule is meant to surface,
             so bcdDevice stays in.
        bDeviceClass / bDeviceSubClass / bDeviceProtocol
          -- the top-level function claim.
        bNumConfigurations
          -- adding a configuration is a structural change.

        per configuration:
          bNumInterfaces
          self-powered bit of bmAttributes
            -- other bits (remote wakeup, reserved) vary with negotiation.
          per interface:
            bInterfaceNumber, bAlternateSetting, bNumEndpoints,
            bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol

    What it drops, and why:

        bcdUSB, bMaxPacketSize0        -- speed negotiation, differs per port.
        bMaxPower                       -- unit differs by USB generation and
                                           the value itself varies with the
                                           negotiated speed.
        endpoint descriptors            -- wMaxPacketSize and bInterval depend
                                           on the negotiated speed; SuperSpeed
                                           endpoints have companion descriptors
                                           (bDescriptorType 0x30) that a USB2
                                           enumeration lacks entirely.
        string indices                  -- iManufacturer etc. index into the
                                           string table; the STRINGS are still
                                           in the identity key via serial, and
                                           two enumerations can renumber the
                                           same strings.

    What a NEW interface still trips: bNumInterfaces changes, the interface
    list gains an entry with a new (class, subclass, protocol) triple, and
    both feed the hash. A BadUSB that reflashes a storage device to add a
    keyboard interface still drifts -- which is the case the whole ledger
    exists for.

    The raw blob is not thrown away: raw_descriptor_hash() below hashes the
    full bytes for forensics, and record() stores it alongside so the ledger
    can still answer "did any byte at all change" without letting that
    question be the one the CRITICAL rule fires on.
    """
    ds = getattr(dev, "descriptor_set", None)
    if ds is None:
        # No parseable descriptors -- fall back to hashing the raw bytes so
        # something is still recorded, but a device we could not parse also
        # cannot be trusted, so this path is only reached for the alarm-worthy
        # case anyway. None means "nothing to fingerprint at all".
        raw = getattr(dev, "raw_descriptors", None)
        return hashlib.sha256(raw).hexdigest() if raw else None

    d = ds.device
    parts = [
        f"v={d.vendor_id:04x}",
        f"p={d.product_id:04x}",
        f"r={d.device_version:04x}",
        f"c={d.device_class:02x}.{d.device_subclass:02x}.{d.device_protocol:02x}",
        f"nc={d.num_configurations}",
    ]
    for cfg in ds.configs:
        parts.append(f"|cfg ni={cfg.num_interfaces} sp={int(cfg.self_powered)}")
        # Sorted so a device that renumbers its interface list between
        # enumerations (legal, and does happen) does not read as drift. The
        # tuple ORDER carries the meaning; the LIST order does not.
        for i in sorted(cfg.interfaces,
                        key=lambda x: (x.number, x.alternate)):
            parts.append(
                f"i={i.number}.{i.alternate} ne={i.num_endpoints} "
                f"cls={i.interface_class:02x}.{i.interface_subclass:02x}."
                f"{i.interface_protocol:02x}")
    canonical = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def raw_descriptor_hash(dev) -> Optional[str]:
    """
    SHA-256 of the ENTIRE descriptor blob, byte-for-byte.

    Kept beside the normalized fingerprint for forensics. It is what the
    ledger displays and what --history shows when the operator asks "did
    anything at all differ between visits", but it is NEVER the field
    LedgerAnalyzer compares -- see descriptor_fingerprint above for why.

    None on a device whose raw descriptors were not captured; the ledger
    stores "-" in that case, so the field always carries a string.
    """
    raw = getattr(dev, "raw_descriptors", None)
    return hashlib.sha256(raw).hexdigest() if raw else None


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
        self.entries.clear()
        self.load_error = None
        if not self.path.exists():
            return
        try:
            from .securefs import read_json_file
            data = read_json_file(self.path)
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            # A corrupt ledger must not stop the gate from working. Losing
            # history is an inconvenience; refusing to admit a keyboard because
            # a JSON file is malformed is a lockout.
            self.load_error = f"{exc}"
            return
        if not isinstance(data, dict):
            self.load_error = "state file is not a JSON object"
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

        # The file-level marker is propagated INTO each entry. Held at the
        # file level rather than duplicated per-entry because the scheme is a
        # property of how the ledger was written, not of any one device: every
        # entry in one file was fingerprinted the same way. Absent means the
        # old raw-blob scheme, which triggers the one-time baseline clear in
        # from_raw.
        scheme = data.get("fingerprint_scheme")
        skipped = 0
        for key, raw in entries.items():
            if not isinstance(key, str):
                skipped += 1
                continue
            if isinstance(raw, dict) and "fingerprint_scheme" not in raw:
                raw = dict(raw, fingerprint_scheme=scheme)
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
                # Marker for the descriptor-fingerprint algorithm used by
                # every entry in this file. "normalized-v1" is the current
                # scheme: it hashes the parsed device / interface identity
                # and drops the bus-negotiated fields (bcdUSB, bMaxPower,
                # endpoint packet sizes, SuperSpeed companion descriptors)
                # so a controller swap does not fire the drift alarm.
                # A file written without this key is treated as the old
                # raw-blob scheme -- see Entry.from_raw for the migration.
                "fingerprint_scheme": "normalized-v1",
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

    def record(self, dev, decision: str, approved: bool = False) -> None:
        """
        Add or update this device's history. Call after every decision.

        `approved` is what moves the drift baseline, and nothing else does.

        WHY THE CALLER HAS TO SAY (the bug this parameter fixes)
        --------------------------------------------------------
        This method used to overwrite `descriptor_hash` unconditionally, and
        that field was what LedgerAnalyzer compared against. So every route
        that records a decision BEFORE the device is judged destroyed the
        alarm, on the device it was about:

          * daemon._hold_until_unlocked() records "held: screen locked" the
            moment a device arrives while the screen is locked. When the user
            comes back, _drain_pending() -> _on_add(was_held=True) re-runs the
            analyzers against a ledger that has already adopted the held
            device's blob as the reference. No drift, no CRITICAL, and the
            prompt drops to a plain [y]es/[a]lways/[N]o -- for a device that
            was swapped in while nobody was there, which is the precise threat
            the lock policy exists for and the one case where nobody ever saw
            the first alarm.
          * a refusal, or a prompt that timed out into one, did the same: the
            alarm fired once, the ledger then learned the attacker's blob, and
            a replug read clean.

        A decision recorded is not a decision endorsed. Only an approval means
        "this is my device now", so only an approval moves the reference. Every
        other decision leaves it where it was, and the device keeps failing the
        comparison until a human actually says yes -- which is what stops the
        second attempt from being cheaper than the first.
        """
        key = identity_of(dev)
        digest = descriptor_fingerprint(dev) or "-"
        raw = raw_descriptor_hash(dev) or "-"
        # "-" is the placeholder for a device whose descriptors could not be
        # read. It must never become a baseline: the next readable appearance
        # would then differ from it and be reported as drift, which is a
        # CRITICAL raised by our own failure to read rather than by the device.
        pinnable = digest != "-"
        now = time.time()
        entry = self.entries.get(key)

        if entry is None:
            self.entries[key] = Entry(
                identity=key, descriptor_hash=digest,
                first_seen=now, last_seen=now,
                ports=[dev.name], decisions=[decision],
                known_hashes=[digest],
                # The first sighting sets the reference whatever the decision
                # was: it is the only evidence there is, and a first sighting is
                # never itself a finding.
                baseline_hash=digest if pinnable else "",
                raw_hash=raw,
            )
            return

        entry.last_seen = now
        entry.times_seen += 1
        entry.descriptor_hash = digest      # most recent, for display only
        entry.raw_hash = raw                # ditto -- forensics only
        if pinnable and (approved or not entry.baseline_hash):
            entry.baseline_hash = digest
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
