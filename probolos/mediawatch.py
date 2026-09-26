"""
Media changes inside a storage host that is already admitted.

THE GAP THIS COVERS, AND WHAT IT DOES NOT
-----------------------------------------
Probolos gates USB DEVICES. A card reader is the USB device; the card is a SCSI
medium inside it. Inserting, removing or swapping a card is a unit attention in
the already-bound usb-storage/uas driver: no re-enumeration, no USB uevent, no
`authorized` decision point. So once a reader is admitted, every later card
enters without passing the gate. A USB stick re-enumerates on every connect; a
trusted reader is a permanent SCSI host.

The medium change IS visible at the block layer: the reader's whole disk
(sdX, one per LUN) sits at size 0 while empty, and a `change` uevent reports
the new medium. This module listens there.

It is a DETECTION layer, separate from the pre-authorization quarantine:

  * There is no per-medium `authorized` knob, so a card cannot be held the way
    a device is. The quarantine claim does not extend to cards.
  * What reading gives is structure: a partition table, sizes, filesystem
    signatures, compared with what this slot has seen before. A crafted exFAT
    that exploits the kernel's exFAT driver looks like ordinary exFAT here.
    Filesystem-parser exploits are kernel fs-driver surface and out of scope.
  * The only enforcement available is coarse: log, or (--media-policy
    deauthorize) switch the WHOLE READER off on a CRITICAL finding.

Two limits are stated wherever the result is shown rather than hidden here:

  * THE AUTOMOUNTER LISTENS TO THE SAME EVENT. udisks2 mounts on this very
    `change`. Unless automount is inhibited for the disk (the udev rule in the
    README sets UDISKS_AUTO=0), the medium may be mounted -- and the kernel fs
    driver may have parsed it -- before or while it is read, and the result is
    post-hoc alerting, not prevention. Each report says which case it was.
  * LATENCY. Medium detection rides on the kernel's disk-event polling
    (disk_check_events): typically one to two seconds, and some readers do
    not report media changes at all. Such a slot is flagged when first seen.

Only hosts this run admitted, or found admitted at startup, are watched, and
only while every function they declare is mass storage.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional

from . import report, rules, storage, sysfs, usbclass

POLICY_LOG = "log"
POLICY_DEAUTHORIZE = "deauthorize"
POLICIES = (POLICY_LOG, POLICY_DEAUTHORIZE)

# Mirrors storage._WHOLE_DISK_NAME: the reader's LUNs are whole sdX disks.
_WHOLE_DISK_NAME = re.compile(r"^sd[a-z]+$")
_SCSI_ADDRESS = re.compile(r"^\d+:\d+:\d+:(\d+)$")
PROC_MOUNTS = "/proc/self/mounts"
EVENTS_DEFAULT_POLL = "/sys/module/block/parameters/events_dfl_poll_msecs"

EMPTY = "empty"
UNREADABLE = "unreadable"


@dataclass
class Host:
    """A storage host being watched: the reader, not any card in it."""
    dev: sysfs.UsbDevice
    resolved: str
    instance: tuple
    # disk name -> EMPTY, UNREADABLE or the layout fingerprint last seen
    slots: Dict[str, str] = field(default_factory=dict)


def layout_fingerprint(medium: storage.MediumReport) -> Optional[str]:
    """
    SHA-256 of what a medium says about its own layout, or None if unread.

    Capacity, scheme, every partition entry, recognised filesystems and GPT
    entry types. Two cards with the same fingerprint are indistinguishable to
    stage 4; that is the granularity drift is measured at.
    """
    if medium is None or medium.error:
        return None
    parts = [f"scheme={medium.scheme}", f"size={medium.size_sectors}"]
    for p in sorted(medium.partitions, key=lambda p: p.index):
        parts.append(f"p{p.index} t={p.type_byte:02x} s={p.start_lba} "
                     f"n={p.sectors} b={int(p.bootable)}")
    for index in sorted(medium.signatures):
        parts.append(f"fs{index}={medium.signatures[index]}")
    for e in medium.gpt_entries:
        parts.append(f"g{e.index} t={e.type_guid} a={e.attributes:x}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def _is_storage_host(dev: sysfs.UsbDevice) -> bool:
    return (dev.instance_id is not None and dev.inspection_safe
            and set(dev.kinds) == {usbclass.KIND_STORAGE})


def _mounted(disk: str) -> bool:
    """Is the disk, or any of its partitions, mounted right now?"""
    pattern = re.compile(rf"^/dev/{re.escape(disk)}\d*$")
    try:
        with open(PROC_MOUNTS) as fh:
            return any(pattern.match(line.split(" ", 1)[0]) for line in fh)
    except OSError:
        return False


def _read(path) -> Optional[str]:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def event_reporting_problem(disk_syspath) -> Optional[str]:
    """Why this slot's media changes may go unseen, or None."""
    events = _read(Path(disk_syspath) / "events")
    if events is None:
        return None                 # older kernel; nothing to say either way
    if "media_change" not in events.split():
        return ("this slot does not report media changes to the kernel; a "
                "card inserted here is seen only when something re-reads it")
    poll = _read(Path(disk_syspath) / "events_poll_msecs")
    if poll == "-1":
        poll = _read(EVENTS_DEFAULT_POLL)
    if poll == "0":
        return ("the kernel is not polling this slot for media changes; "
                "udisks usually does, a headless machine may not")
    return None


class MediaWatch:
    """
    Watches the block devices of admitted storage hosts for medium changes.

    `on_deauthorized(dev, findings)` is called after the reader was switched
    off under the deauthorize policy, so the daemon can forget it was past the
    gate and record the decision.
    """

    def __init__(self, policy: str = POLICY_LOG, ledger=None, json_log=None,
                 rule_config: Optional[rules.RuleConfig] = None,
                 is_locked: Optional[Callable[[], Optional[bool]]] = None,
                 on_deauthorized: Optional[Callable] = None, log=print):
        if policy not in POLICIES:
            raise ValueError(f"unknown media policy: {policy!r}")
        self.policy = policy
        self.ledger = ledger
        self.json_log = json_log
        self.rule_config = rule_config
        self.is_locked = is_locked or (lambda: False)
        self.on_deauthorized = on_deauthorized
        self.log = log
        self.hosts: Dict[str, Host] = {}

    # ---- which hosts ----------------------------------------------------

    def register(self, dev: sysfs.UsbDevice, why: str) -> bool:
        """Start watching `dev` if it is a pure storage host. True if so."""
        if not _is_storage_host(dev):
            return False
        try:
            resolved = os.path.realpath(dev.syspath)
        except (OSError, ValueError):
            return False
        self.hosts[dev.name] = Host(dev=dev, resolved=resolved,
                                    instance=dev.instance_id)
        self.log(f"[◉] watching media in {report.one_liner(dev)} ({why})")
        return True

    def unregister(self, name: str) -> None:
        self.hosts.pop(name, None)

    def _host_of(self, disk_syspath: str) -> Optional[Host]:
        try:
            resolved = os.path.realpath(disk_syspath)
        except (OSError, ValueError):
            return None
        for name, host in list(self.hosts.items()):
            if not resolved.startswith(host.resolved + "/"):
                continue
            # A sysfs name is a port. The instance is the device.
            try:
                st = os.stat(host.resolved)
                same = (st.st_dev, st.st_ino) == host.instance
            except OSError:
                same = False
            if not same:
                self.unregister(name)
                return None
            return host
        return None

    # ---- events ---------------------------------------------------------

    def handle(self, action: str, sys_path: str, properties=None) -> None:
        """One block uevent. Anything not a watched whole disk is ignored."""
        properties = properties or {}
        disk = Path(sys_path).name
        if not _WHOLE_DISK_NAME.match(disk):
            return
        if properties.get("DEVTYPE", "disk") != "disk":
            return
        if action == "remove":
            for host in self.hosts.values():
                host.slots.pop(disk, None)
            return
        if action not in ("add", "change"):
            return
        host = self._host_of(sys_path)
        if host is None:
            return

        lun = self._lun(sys_path)
        first_sight = disk not in host.slots
        if first_sight:
            problem = event_reporting_problem(sys_path)
            if problem:
                self.log(f"[!] {host.dev.name} LUN {lun} ({disk}): {problem}")

        size = storage.read_size_sectors(f"/dev/{disk}")
        if not size:
            if host.slots.get(disk) not in (None, EMPTY):
                self.log(f"[◌] medium removed — {host.dev.label()} "
                         f"LUN {lun} ({disk})")
                self._audit(host, disk, lun, "removed")
            host.slots[disk] = EMPTY
            return

        media_change = properties.get("DISK_MEDIA_CHANGE") == "1"
        inhibited = (properties.get("UDISKS_IGNORE") == "1"
                     or properties.get("UDISKS_AUTO") == "0")
        mounted_before = _mounted(disk)
        medium = self._inspect(disk)
        fingerprint = layout_fingerprint(medium)
        state = fingerprint or UNREADABLE
        # Partition rescans and repeated polls produce more than one `change`
        # for one medium. Only the kernel's own media-change flag, or a
        # different layout, is a new medium.
        if not media_change and host.slots.get(disk) == state:
            return
        host.slots[disk] = state

        drift = None
        drift_known = False
        if self.ledger is not None and fingerprint is not None:
            baseline, seen = self.ledger.record_media(host.dev, lun,
                                                      fingerprint)
            if baseline is not None and baseline != fingerprint:
                drift, drift_known = baseline, seen
            error = self.ledger.save()
            if error:
                self.log(f"[!] could not write ledger: {error}")

        findings = sorted(
            rules.storage_findings(medium, self.rule_config)
            + rules.media_findings(medium, drift=drift,
                                   drift_known=drift_known,
                                   locked=self.is_locked() is True,
                                   config=self.rule_config),
            key=lambda f: f.severity, reverse=True)

        timing = self._timing(mounted_before, inhibited)
        self.log("")
        self.log(f"[▣] MEDIUM CHANGE — {report.one_liner(host.dev)} "
                 f"LUN {lun} ({disk})"
                 + (" — first medium seen in this slot" if first_sight
                    else ""))
        self.log(report.render_medium(medium, findings))
        self.log(f"  {timing}")
        if medium.scheme == "gpt" and not medium.gpt_entries_parsed:
            self.log("  GPT entries are not where the header read reaches; "
                     "EFI and hidden-partition checks did not run.")

        enforcement = self._enforce(host, findings)
        self._audit(host, disk, lun, "inserted", medium=medium,
                    fingerprint=fingerprint, drift=drift, findings=findings,
                    timing=timing, enforcement=enforcement)
        self.log("")

    # ---- pieces ---------------------------------------------------------

    @staticmethod
    def _lun(disk_syspath: str) -> str:
        try:
            address = Path(os.path.realpath(Path(disk_syspath) / "device")).name
        except (OSError, ValueError):
            return "?"
        match = _SCSI_ADDRESS.match(address)
        return match.group(1) if match else "?"

    @staticmethod
    def _inspect(disk: str) -> storage.MediumReport:
        """Stage 4's own inspection, on the same terms: read-only, bounded."""
        node = f"/dev/{disk}"
        deadline = time.monotonic() + 1.5
        pending = sysfs.block_node_pending(node)
        while pending is not None and time.monotonic() < deadline:
            time.sleep(0.02)
            pending = sysfs.block_node_pending(node)
        if pending is not None:
            return storage.MediumReport(
                device=node, error="its block device did not become ready",
                detail=f"{node}: {pending}")
        medium = storage.inspect_safely(node, open_fn=sysfs.open_block_device)
        if medium.error and not medium.timed_out:
            medium.detail = f"{node}: {medium.error}"
            medium.error = "its block device could not be read"
        return medium

    @staticmethod
    def _timing(mounted_before: bool, inhibited: bool) -> str:
        if mounted_before:
            return ("automount: the medium was ALREADY MOUNTED when it was "
                    "read -- this is post-hoc alerting, not prevention")
        if inhibited:
            return ("automount: inhibited for udisks on this disk, so this "
                    "read came first (other automounters are not covered)")
        return ("automount: NOT inhibited on this disk -- udisks may mount it "
                "during or after this read; treat this as post-hoc alerting")

    def _enforce(self, host: Host, findings) -> str:
        if rules.worst(findings) < rules.Severity.CRITICAL:
            return "logged"
        if self.policy != POLICY_DEAUTHORIZE:
            self.log("  CRITICAL finding; --media-policy is 'log', so the "
                     "reader stays authorized.")
            return "logged (policy: log)"
        # The last look at the instance before the write: the direct backend
        # has no gate to make this check for it.
        try:
            st = os.stat(host.resolved)
            if (st.st_dev, st.st_ino) != host.instance:
                self.unregister(host.dev.name)
                return "not enforced: the reader was replaced"
            sysfs.set_authorized(host.dev.syspath, 0)
        except OSError as exc:
            self.log(f"[!!] COULD NOT DEAUTHORIZE the reader "
                     f"{host.dev.name}: {exc}")
            self.log(f"[!!] The card in it is still reachable. Remove it, or "
                     f"unplug the reader.")
            return "deauthorization failed"
        self.unregister(host.dev.name)
        self.log(f"[-] READER DEAUTHORIZED — {report.one_liner(host.dev)}")
        self.log("    The whole reader is off, not only this card. Replug it "
                 "to have it gated again.")
        if self.on_deauthorized is not None:
            self.on_deauthorized(host.dev, findings)
        return "reader deauthorized"

    def _audit(self, host: Host, disk: str, lun: str, what: str, *,
               medium=None, fingerprint=None, drift=None, findings=(),
               timing=None, enforcement=None) -> None:
        if not self.json_log:
            return
        dev = host.dev
        entry = {
            "time": time.time(),
            "event": "media-change",
            "action": what,
            "device": dev.name,
            "vendor_id": dev.vendor_id,
            "product_id": dev.product_id,
            "serial": dev.serial,
            "disk": disk,
            "lun": lun,
        }
        if what == "inserted":
            entry.update({
                "layout": fingerprint,
                "baseline": drift,
                "verdict": rules.worst(findings).label,
                "findings": [{"rule": f.rule_id, "severity": f.severity.label,
                              "title": f.title} for f in findings],
                "automount": timing,
                "enforcement": enforcement,
                "medium": {"examined": medium.error is None,
                           "reason": medium.error, "detail": medium.detail},
            })
        try:
            from .securefs import append_json_line
            append_json_line(self.json_log, entry)
        except OSError as exc:
            self.log(f"[!] could not write log: {exc}")
