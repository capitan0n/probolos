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
        for key, raw in (data.get("devices") or {}).items():
            try:
                self.devices[key] = TrustedDevice(**raw)
            except TypeError:
                continue  # skip malformed entries rather than trusting them

    def save(self) -> Optional[str]:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({
                "schema": SCHEMA_VERSION,
                "devices": {k: asdict(v) for k, v in self.devices.items()},
            }, indent=1))
            tmp.replace(self.path)
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
