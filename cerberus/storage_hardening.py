"""
storage_hardening.py — Defensive checks for stage 4 (storage inspection).

THE PROBLEM (#3 from the gap list)
----------------------------------
storage.py reads the MBR/GPT of a hostile device read-only. It does NOT mount —
good. BUT the parser trusts numbers the device controls:

  1. part.start_lba * SECTOR: a device declares start_lba = 0xFFFFFFFF.
     The offset becomes ~2 TB. seek()+read() there, on a device that does NOT
     have that much space, can hang the driver or fail unpredictably.

  2. end_lba = start_lba + sectors: with start and sectors near 2^32, the sum
     exceeds the size. The "partition past end of device" comparison breaks if
     you do not do it carefully.

  3. Four partitions that ALL point at huge offsets: four seeks to 2 TB = four
     possible hangs. The count is bounded (4 in the MBR), but the cost per read
     is not.

THE SOLUTION: validate EVERY partition BEFORE reading anything from it. A
partition that does not fit inside the device's declared size is either
corrupt or hostile — in both cases, we do not read it.

This is the SAME pattern as descriptors_safe.py: do not trust lengths the
device declares; cross-check them against reality (here, the real size from
sysfs).
"""

from __future__ import annotations

from typing import List, Optional, Tuple

SECTOR = 512

# Maximum plausible device size in sectors (~16 TB). Above this, the
# declaration is almost certainly hostile for a USB storage device.
MAX_PLAUSIBLE_SECTORS = 32 * 1024 * 1024 * 1024  # 16 TiB / 512

# Maximum offset we will ever seek to. Beyond this, we do not read.
MAX_SEEK_OFFSET = MAX_PLAUSIBLE_SECTORS * SECTOR


class StorageValidationError(ValueError):
    """Invalid partition structure — leads to skipping, not crash/hang."""


def validate_partition(start_lba: int,
                       sectors: int,
                       device_sectors: Optional[int]) -> Tuple[bool, str]:
    """
    Is it safe to read from this partition?

    Returns (ok, reason). If ok is False, the caller must NOT seek/read from it
    — just record it as suspicious and move on.

    The checks, in order:
      - non-negative / non-zero (a partition with sectors=0 is an empty slot)
      - start does not exceed the maximum plausible offset
      - end = start + sectors does not overflow the logic (Python ints are
        unbounded, so "overflow" here means "exceeds the size")
      - if we know the real size, the partition fits inside it
    """
    if start_lba < 0 or sectors < 0:
        return False, f"negative start/sectors ({start_lba}/{sectors})"

    if sectors == 0:
        return False, "empty slot (sectors=0)"

    if start_lba > MAX_PLAUSIBLE_SECTORS:
        return False, f"start_lba {start_lba} beyond any plausible size"

    end_lba = start_lba + sectors
    if end_lba > MAX_PLAUSIBLE_SECTORS:
        return False, f"partition ends at {end_lba} — unrealistic"

    if device_sectors is not None:
        # The strongest check: the real size from sysfs. A partition that
        # claims to extend past the physical disk is the classic
        # "partition extends past end of device" — corrupt or hostile.
        if start_lba >= device_sectors:
            return False, (f"partition starts at sector {start_lba} but the "
                           f"device has only {device_sectors}")
        if end_lba > device_sectors:
            return False, (f"partition ends at {end_lba} but the device "
                           f"has only {device_sectors} sectors")

    return True, "ok"


def safe_read_offset(start_lba: int, device_sectors: Optional[int]) -> Optional[int]:
    """
    The byte offset to seek to, ONLY if it is safe. Otherwise None.

    Use in storage.inspect, in place of the raw `part.start_lba * SECTOR`:

        offset = safe_read_offset(part.start_lba, report.size_sectors)
        if offset is None:
            report.suspicious.append(f"partition {part.index}: unsafe offset")
            continue
        chunk = _read_at(device, offset, SECTOR, open_fn)
    """
    ok, _reason = validate_partition(start_lba, 1, device_sectors)
    if not ok:
        return None
    offset = start_lba * SECTOR
    if offset > MAX_SEEK_OFFSET:
        return None
    return offset


def device_size_sane(device_sectors: Optional[int]) -> Tuple[bool, str]:
    """
    Checks whether the declared device size is itself plausible.

    A device declaring 100 PB via sysfs is trying to cause an overflow or a
    huge allocation somewhere downstream. We catch it early.
    """
    if device_sectors is None:
        return True, "unknown size (will rely on per-partition checks)"
    if device_sectors < 0:
        return False, f"negative size: {device_sectors}"
    if device_sectors > MAX_PLAUSIBLE_SECTORS:
        return False, (f"declares {device_sectors} sectors "
                       f"(~{device_sectors * SECTOR // (10**12)} TB) — unrealistic")
    return True, "ok"


def filter_safe_partitions(partitions: List,
                           device_sectors: Optional[int]) -> Tuple[List, List[str]]:
    """
    Splits partitions into (safe to read, suspicious).

    Returns (safe_list, suspicion_messages). The suspicious ones are NOT read
    but ARE reported — the very existence of an impossible partition is a
    finding.
    """
    safe = []
    suspicious = []
    for part in partitions:
        start = getattr(part, "start_lba", 0)
        sectors = getattr(part, "sectors", 0)
        ok, reason = validate_partition(start, sectors, device_sectors)
        if ok:
            safe.append(part)
        else:
            idx = getattr(part, "index", "?")
            if reason != "empty slot (sectors=0)":  # empty slots are not suspicious
                suspicious.append(f"partition {idx}: {reason}")
    return safe, suspicious
