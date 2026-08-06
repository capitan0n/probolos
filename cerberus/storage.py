"""
Stage 4: looking inside a storage device without mounting it.

WHY NOT JUST MOUNT IT
---------------------
Mounting hands the device's data to a kernel filesystem driver -- tens of
thousands of lines of C that were written assuming the disk is not hostile.
A deliberately corrupted filesystem image is a well-established way to attack
that code, and the automount in a desktop session will do it the moment the
device is authorized, before anyone has looked at anything.

So Cerberus reads the raw block device itself, as bytes, and parses only the
partition table and filesystem signatures -- structures simple enough to parse
safely in Python, with every length checked. Nothing is executed, nothing is
interpreted as a filesystem, and the device is opened read-only.

WHAT IT LOOKS FOR
-----------------
Structural contradictions, in the same spirit as the descriptor rules: places
where the medium disagrees with itself.

    * a partition that extends past the end of the device
    * partitions that overlap each other
    * a filesystem signature that does not match the declared partition type
    * a GPT that disagrees with its own protective MBR
    * an unusually large unallocated gap before the first partition

None of these are proof of anything. All of them are things a person formatting
a USB stick normally does not produce, and the first two are impossible on
honestly-made media.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not walk directories, read files, or look for autorun.inf and friends.
That would mean implementing FAT and NTFS parsing -- reintroducing exactly the
attack surface this stage exists to avoid, in a language that is safer but in
code far less reviewed than the kernel's. Content inspection at that depth
belongs in a sandbox, not in the admission path.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import storage_hardening

SECTOR = 512
MBR_SIGNATURE = 0xAA55
GPT_SIGNATURE = b"EFI PART"
PROTECTIVE_MBR_TYPE = 0xEE

# How much we read. Enough for the MBR, the GPT header and its first entries,
# plus the start of the first partition to sniff a filesystem signature.
HEADER_READ = SECTOR * 34

# Partition type bytes seen on ordinary removable media.
FAT_TYPES = {0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E}
NTFS_EXFAT_TYPES = {0x07}
LINUX_TYPES = {0x83}
EXTENDED_TYPES = {0x05, 0x0F}


@dataclass
class Partition:
    index: int
    bootable: bool
    type_byte: int
    start_lba: int
    sectors: int

    @property
    def end_lba(self) -> int:
        return self.start_lba + self.sectors


@dataclass
class MediumReport:
    """What the raw medium says about itself."""
    device: str = ""
    size_sectors: Optional[int] = None
    scheme: str = "unknown"          # mbr / gpt / none
    partitions: List[Partition] = field(default_factory=list)
    signatures: dict = field(default_factory=dict)  # partition index -> fs name
    suspicious: List[str] = field(default_factory=list)  # impossible/hostile partitions
    error: Optional[str] = None

    @property
    def inspected(self) -> bool:
        return self.error is None and self.scheme != "unknown"


# --------------------------------------------------------------------------
# Locating the block device
# --------------------------------------------------------------------------

def find_block_devices(usb_syspath) -> List[str]:
    """
    Find /dev/sdX nodes belonging to one USB device.

    Walks the sysfs tree beneath the device looking for `block/<name>`, the
    same ancestry approach used for input nodes -- and for the same reason:
    inspecting the wrong disk would be considerably worse than inspecting none.
    """
    import os

    root = os.path.realpath(str(usb_syspath))
    found = []
    for dirpath, dirnames, _files in os.walk(root):
        if os.path.basename(dirpath) == "block":
            for name in dirnames:
                found.append(f"/dev/{name}")
            dirnames[:] = []
    return sorted(set(found))


def read_size_sectors(device: str) -> Optional[int]:
    """Device size in 512-byte sectors, from sysfs (no privileges needed)."""
    name = Path(device).name
    try:
        return int(Path(f"/sys/block/{name}/size").read_text().strip())
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def parse_mbr(data: bytes) -> List[Partition]:
    """Parse the four primary partition entries of an MBR."""
    if len(data) < SECTOR:
        return []
    if struct.unpack_from("<H", data, 510)[0] != MBR_SIGNATURE:
        return []

    partitions = []
    for i in range(4):
        offset = 446 + i * 16
        status, _c1, _c2, _c3, ptype, _c4, _c5, _c6, start, sectors = \
            struct.unpack_from("<BBBBBBBBII", data, offset)
        if ptype == 0 or sectors == 0:
            continue        # empty slot
        partitions.append(Partition(index=i, bootable=bool(status & 0x80),
                                    type_byte=ptype, start_lba=start,
                                    sectors=sectors))
    return partitions


def parse_gpt_header(data: bytes) -> Optional[dict]:
    """Read the GPT header at LBA 1, if present."""
    if len(data) < SECTOR * 2:
        return None
    header = data[SECTOR:SECTOR * 2]
    if header[:8] != GPT_SIGNATURE:
        return None
    (_sig, revision, header_size, _crc, _reserved, current_lba, backup_lba,
     first_usable, last_usable) = struct.unpack_from("<8sIIIIQQQQ", header, 0)
    return {
        "revision": revision,
        "header_size": header_size,
        "current_lba": current_lba,
        "backup_lba": backup_lba,
        "first_usable": first_usable,
        "last_usable": last_usable,
    }


def sniff_filesystem(data: bytes) -> Optional[str]:
    """
    Identify a filesystem from its signature bytes alone.

    Signature matching only -- no structure is followed, no length inside the
    image is trusted. The point is to compare what the medium CLAIMS in its
    partition table against what is actually written there.
    """
    if len(data) < 512:
        return None
    if data[3:11] in (b"NTFS    ",):
        return "NTFS"
    if data[3:11] == b"EXFAT   ":
        return "exFAT"
    if data[54:59] == b"FAT12":
        return "FAT12"
    if data[54:59] == b"FAT16":
        return "FAT16"
    if data[82:87] == b"FAT32":
        return "FAT32"
    if len(data) > 0x438 + 2:
        magic = struct.unpack_from("<H", data, 0x438)[0]
        if magic == 0xEF53:
            return "ext2/3/4"
    if data[:4] == b"\x28\xb5\x2f\xfd" or data[:9] == b"\x1c\x00\x00\x00":
        return None
    if data[0x10040:0x10044] == b"_BHRfS_M" if len(data) > 0x10044 else False:
        return "btrfs"
    return None


def _inspect_worker(device: str, conn, fd=None) -> None:
    """Runs inspect() in a child so a stalled read can be killed."""
    try:
        open_fn = (lambda _dev: fd) if fd is not None else None
        conn.send(("ok", inspect(device, open_fn=open_fn)))
    except Exception as exc:              # noqa: BLE001 -- fail closed
        conn.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        conn.close()


def inspect_safely(device: str, timeout: float = 10.0,
                   open_fn=None) -> MediumReport:
    """
    inspect() under a hard time limit. This is what the daemon should call.

    A storage device can stall a read forever -- ordinary for flaky USB, a
    deliberate move for a hostile one. Without a bound the daemon freezes, and
    with the watchdog running that freeze becomes the watchdog opening the gate
    for the whole system: a stall in the SECURITY SCAN causing a system-wide
    fail-open. So inspect() runs in a child process that is killed if it
    overruns, and the timeout becomes a finding -- a device that will not let
    itself be inspected has told you something.

    A child process rather than signal.alarm, for two independent reasons:
    inspect() runs off the main thread and POSIX signals are delivered to the
    main thread only, and a read wedged in uninterruptible sleep ignores
    signals entirely. Only killing the process reliably ends it.

    This wraps the whole of inspect() rather than each os.read, so BOTH read
    paths (the header read and read_at) are bounded by one guard.

    WHY open_fn IS CALLED IN THE PARENT
    -----------------------------------
    Under --privsep, open_fn asks the root gate for a descriptor over a socket
    the child does not have. So the parent opens (a bounded, fast request) and
    the child only READS (the unbounded, stallable part). The fd crosses the
    fork by inheritance, which is why the child is handed a plain integer and
    a trivial open_fn that returns it.
    """
    import multiprocessing
    import os as _os

    fd = None
    try:
        if open_fn is not None:
            fd = open_fn(device)
    except OSError as exc:
        return MediumReport(device=device, error=str(exc))

    parent_conn, child_conn = multiprocessing.Pipe()
    proc = multiprocessing.Process(
        target=_inspect_worker, args=(device, child_conn, fd), daemon=True)
    try:
        proc.start()
        proc.join(timeout)
        if proc.is_alive():
            proc.terminate()
            proc.join(1.0)
            if proc.is_alive():
                proc.kill()
            # `inspected` stays False (scheme unknown), so no rule mistakes a
            # stalled device for one that passed. The silence is the finding.
            return MediumReport(
                device=device,
                error=f"device did not respond within {timeout:.0f}s -- "
                      f"inspection abandoned")
        if parent_conn.poll():
            kind, payload = parent_conn.recv()
            return payload if kind == "ok" else MediumReport(device=device,
                                                             error=payload)
        return MediumReport(device=device,
                            error="inspection process produced no result")
    finally:
        # The child has its own copy (or was killed); ours must not leak. This
        # matters most on the timeout path, where the child never ran finally.
        if fd is not None:
            try:
                _os.close(fd)
            except OSError:
                pass


def inspect(device: str, open_fn=None) -> MediumReport:
    """
    Read and parse the start of a block device. Never mounts, never writes.

    `open_fn` allows the privileged gate to supply an already-open read-only
    descriptor under privilege separation, exactly as with input nodes.
    """
    import os

    report = MediumReport(device=device)
    report.size_sectors = read_size_sectors(device)

    fd = None
    try:
        fd = open_fn(device) if open_fn else os.open(device, os.O_RDONLY)
        data = os.read(fd, HEADER_READ)
    except OSError as exc:
        report.error = str(exc)
        return report
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    if len(data) < SECTOR:
        report.error = f"only {len(data)} bytes readable"
        return report

    partitions = parse_mbr(data)
    gpt = parse_gpt_header(data)

    if gpt is not None:
        report.scheme = "gpt"
        report.partitions = partitions          # the protective MBR entries
    elif partitions:
        report.scheme = "mbr"
        report.partitions = partitions
    else:
        # No partition table. Common and legitimate: many USB sticks are
        # formatted as a "superfloppy", with a filesystem written directly to
        # the medium. Sniff it so this is reported as a fact, not an anomaly.
        report.scheme = "none"
        fs = sniff_filesystem(data)
        if fs:
            report.signatures[-1] = fs
        return report

    # Read the first sector of each partition to see what is actually there.
    for part in report.partitions:
        if part.type_byte == PROTECTIVE_MBR_TYPE:
            continue
        # HARDENING: never seek to a device-controlled offset without
        # checking it fits inside the real device first. A partition
        # claiming start_lba=0xFFFFFFFF would otherwise seek to ~2 TB.
        offset = storage_hardening.safe_read_offset(
            part.start_lba, report.size_sectors)
        if offset is None:
            report.suspicious.append(
                f'partition {part.index}: start_lba {part.start_lba} '
                f'does not fit the device; not read')
            continue
        chunk = _read_at(device, offset, SECTOR, open_fn)
        if chunk:
            fs = sniff_filesystem(chunk)
            if fs:
                report.signatures[part.index] = fs

    return report


def _read_at(device: str, offset: int, length: int, open_fn=None) -> bytes:
    """One bounded read at an offset. Failures are silent and non-fatal."""
    import os

    fd = None
    try:
        fd = open_fn(device) if open_fn else os.open(device, os.O_RDONLY)
        os.lseek(fd, offset, os.SEEK_SET)
        return os.read(fd, length)
    except OSError:
        return b""
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def type_name(type_byte: int) -> str:
    names = {
        0x00: "empty", 0x01: "FAT12", 0x04: "FAT16", 0x05: "extended",
        0x06: "FAT16B", 0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32 LBA",
        0x0E: "FAT16 LBA", 0x0F: "extended LBA", 0x82: "Linux swap",
        0x83: "Linux", 0x8E: "Linux LVM", 0xEE: "GPT protective",
        0xEF: "EFI system",
    }
    return names.get(type_byte, f"type 0x{type_byte:02x}")


def expected_filesystems(type_byte: int) -> Optional[set]:
    """
    What a partition of this declared type should plausibly contain.

    Returns None when the type does not imply a filesystem, so no judgement is
    made -- silence is better than a guess.
    """
    if type_byte in FAT_TYPES:
        return {"FAT12", "FAT16", "FAT32", "exFAT"}
    if type_byte in NTFS_EXFAT_TYPES:
        return {"NTFS", "exFAT", "FAT32"}
    if type_byte in LINUX_TYPES:
        return {"ext2/3/4", "btrfs"}
    return None
