"""
Remembering decisions, so the tool can be used every day.

THE PROBLEM THIS SOLVES
-----------------------
Until now Cerberus asked about every device, every time. That makes it a
demonstration, not a tool: a person who is asked the same question about their
own mouse twice a day will stop reading the question, and shortly afterwards
will stop running the program. A security tool nobody runs protects nothing.

So approved devices can be remembered. But trust here is deliberately narrower
than an allowlist in most tools, in three ways that matter:

WHAT IS TRUSTED IS AN EXACT DEVICE, NOT AN IDENTITY
    The key includes a SHA-256 of the raw descriptor blob. A device that
    presents the same vendor, product and serial but different descriptors is
    not the trusted device -- it is something claiming to be it. This is the
    same evidence the drift detector uses, applied at the moment it matters
    most: when deciding whether to let something in without asking.

    This is what makes the trust store meaningfully different from a VID/PID
    allowlist, which a cloned descriptor set defeats completely.

TRUST NEVER OVERRIDES EVIDENCE
    A trusted device that produces a CRITICAL finding is still stopped and
    still asked about. Trust decides whether to ask a question that has no
    troubling answer; it cannot silence one that does. A device that was
    trustworthy last week and is doing something alarming today is exactly the
    case the tool exists for.

TRUST IS VISIBLE AND REVOCABLE
    `--trusted` lists it, `--forget` removes it. A trust store you cannot
    inspect is a liability, because you cannot answer "what does this machine
    currently let in without asking?"
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import atomicio

SCHEMA_VERSION = 1


def default_path() -> Path:
    """Beside the ledger, and with the same root/user split."""
    import os
    if os.geteuid() == 0:
        return Path("/var/lib/cerberus/trusted.json")
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "cerberus" / "trusted.json"


@dataclass
class TrustedDevice:
    key: str                       # identity + descriptor hash
    identity: str                  # vendor:product:serial, for display
    label: str                     # human name, for display
    descriptor_hash: str
    trusted_at: float
    last_seen: float
    times_admitted: int = 0
    note: str = ""
    ports: List[str] = field(default_factory=list)

    @classmethod
    def from_raw(cls, key: str, raw) -> Optional["TrustedDevice"]:
        """
        Build a TrustedDevice from untrusted JSON, or None if it is not one.

        The ledger already validates this way; the trust store did not, which
        was backwards -- the ledger is history, but THIS file decides whether a
        device is admitted without asking. `TrustedDevice(**raw)` accepted
        whatever types the file happened to contain, so a hand-edited or
        hostile store could put a non-string where a string is expected and
        have it flow into comparisons and display.

        Two extra rules beyond the ledger's, both specific to trust meaning
        admission:

          * the entry's own `key` field must match the dict key it was filed
            under. A mismatch is how forget_index used to raise KeyError and
            make trust un-revocable, and it is also the shape a crafted file
            would take to hide an entry from the revoke path.
          * key and descriptor_hash must be non-empty. An entry with no
            fingerprint pins trust to nothing.
        """
        if not isinstance(raw, dict) or not isinstance(key, str):
            return None

        def as_str(value) -> Optional[str]:
            return value if isinstance(value, str) else None

        def as_time(value) -> Optional[float]:
            # bool is a subclass of int, so exclude it explicitly: JSON `true`
            # is not a timestamp.
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return None
            return float(value)

        entry_key = as_str(raw.get("key"))
        identity = as_str(raw.get("identity"))
        label = as_str(raw.get("label"))
        digest = as_str(raw.get("descriptor_hash"))
        trusted_at = as_time(raw.get("trusted_at"))
        last_seen = as_time(raw.get("last_seen"))

        if not entry_key or not digest or entry_key != key:
            return None
        if identity is None or label is None:
            return None
        if trusted_at is None or last_seen is None:
            return None

        times = raw.get("times_admitted", 0)
        if isinstance(times, bool) or not isinstance(times, int) or times < 0:
            times = 0
        note = as_str(raw.get("note")) or ""
        ports_raw = raw.get("ports")
        ports = ([p for p in ports_raw if isinstance(p, str)]
                 if isinstance(ports_raw, list) else [])

        return cls(key=entry_key, identity=identity, label=label,
                   descriptor_hash=digest, trusted_at=trusted_at,
                   last_seen=last_seen, times_admitted=times,
                   note=note, ports=ports)


def descriptor_hash(dev) -> Optional[str]:
    raw = getattr(dev, "raw_descriptors", None)
    return hashlib.sha256(raw).hexdigest() if raw else None


def identity_of(dev) -> str:
    serial = getattr(dev, "serial", None) or "-"
    return f"{dev.vendor_id}:{dev.product_id}:{serial}"


def key_for(dev) -> Optional[str]:
    """
    The trust key: identity AND descriptor fingerprint together.

    Returns None when the device's descriptors could not be read, which makes
    an unreadable device untrustable by construction -- there is nothing to
    pin the trust to, so it must be asked about every time.
    """
    digest = descriptor_hash(dev)
    if not digest:
        return None
    return f"{identity_of(dev)}#{digest}"


class TrustStore:
    def __init__(self, path: Path = None):
        self.path = Path(path) if path else default_path()
        self.devices: Dict[str, TrustedDevice] = {}
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
            # Fail CLOSED: an unreadable trust store means nothing is trusted,
            # so every device is asked about. The opposite default -- trusting
            # everything when the file is corrupt -- would turn a damaged file
            # into an open door.
            self.load_error = str(exc)
            return
        if data.get("schema") != SCHEMA_VERSION:
            self.load_error = f"unsupported trust schema {data.get('schema')}"
            return
        skipped = 0
        for key, raw in (data.get("devices") or {}).items():
            entry = TrustedDevice.from_raw(key, raw)
            if entry is None:
                # Skipped, never trusted. Counted rather than silently dropped:
                # entries disappearing from a file that grants admission is
                # something the operator should be told about.
                skipped += 1
                continue
            self.devices[key] = entry
        if skipped:
            self.load_error = (f"{skipped} malformed trust entr"
                               f"{'y' if skipped == 1 else 'ies'} ignored")

    def save(self) -> Optional[str]:
        try:
            atomicio.write_json_atomic(self.path, {
                "schema": SCHEMA_VERSION,
                "devices": {k: asdict(v) for k, v in self.devices.items()},
            })
            return None
        except OSError as exc:
            message = str(exc)
            if message == self._last_save_error:
                return None
            self._last_save_error = message
            return message

    # ---------- use ----------

    def lookup(self, dev) -> Optional[TrustedDevice]:
        key = key_for(dev)
        return self.devices.get(key) if key else None

    def is_trusted(self, dev) -> bool:
        return self.lookup(dev) is not None

    def trust(self, dev, note: str = "") -> Optional[TrustedDevice]:
        """Remember this exact device. Returns None if it cannot be pinned."""
        key = key_for(dev)
        if key is None:
            return None
        now = time.time()
        entry = TrustedDevice(
            key=key,
            identity=identity_of(dev),
            label=dev.label() if hasattr(dev, "label") else identity_of(dev),
            descriptor_hash=descriptor_hash(dev) or "",
            trusted_at=now,
            last_seen=now,
            ports=[dev.name] if getattr(dev, "name", None) else [],
            note=note,
        )
        self.devices[key] = entry
        return entry

    def record_admission(self, dev) -> None:
        entry = self.lookup(dev)
        if entry is None:
            return
        entry.last_seen = time.time()
        entry.times_admitted += 1
        if getattr(dev, "name", None) and dev.name not in entry.ports:
            entry.ports.append(dev.name)

    def ordered(self) -> List["TrustedDevice"]:
        """
        Remembered devices in a stable, numbered order (by when trusted).

        Stable ordering matters because the numbers are how a person refers to
        an entry -- "delete rule 3" must mean the same entry every time it is
        listed, the way `ufw status numbered` behaves.
        """
        return sorted(self.devices.values(), key=lambda d: d.trusted_at)

    def forget_index(self, index: int) -> Optional[str]:
        """
        Remove the entry shown at position `index` (1-based, as displayed).

        Returns the identity removed, or None if the number is out of range.
        One at a time by design: a person deleting a rule by number should see
        exactly what went, not a range that might include something they did
        not mean.
        """
        entries = self.ordered()
        if not (1 <= index <= len(entries)):
            return None
        entry = entries[index - 1]
        # Delete by the dict key we actually filed it under, not by entry.key.
        # from_raw now guarantees the two agree, but revocation must not be the
        # thing that breaks if they ever diverge again: a trust store you cannot
        # revoke from is worse than one that lost an entry.
        for dict_key, candidate in list(self.devices.items()):
            if candidate is entry:
                del self.devices[dict_key]
                break
        else:
            self.devices.pop(entry.key, None)
        return entry.identity

    def forget(self, pattern: str) -> List[str]:
        """
        Remove trust for anything whose key, identity or label matches.

        Substring matching on purpose: a person revoking trust knows "the
        Kingston stick", not a SHA-256.
        """
        removed = []
        for key in list(self.devices):
            entry = self.devices[key]
            haystack = f"{entry.key} {entry.identity} {entry.label}".lower()
            if pattern.lower() in haystack:
                removed.append(entry.identity)
                del self.devices[key]
        return removed

    def clear(self) -> int:
        count = len(self.devices)
        self.devices.clear()
        return count
