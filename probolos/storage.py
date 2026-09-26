"""
Stage 4: looking inside a storage device without mounting it.

WHY NOT JUST MOUNT IT
---------------------
Mounting hands the device's data to a kernel filesystem driver -- tens of
thousands of lines of C that were written assuming the disk is not hostile.
A deliberately corrupted filesystem image is a well-established way to attack
that code, and the automount in a desktop session will do it the moment the
device is authorized, before anyone has looked at anything.

So Probolos reads the raw block device itself, as bytes, and parses only the
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
    * a filesystem signature with no filesystem behind it (ISO 9660, UDF)
    * a GPT that disagrees with its own protective MBR
    * an unusually large unallocated gap before the first partition

None of these are proof of anything. All of them are things a person formatting
a USB stick normally does not produce, and the first two are impossible on
honestly-made media.

WHAT IT RECOGNISES, AND WHAT THAT IS WORTH
------------------------------------------
Filesystem detection is a fixed, hand-written set of magics -- NTFS, exFAT,
FAT12/16/32, ext2/3/4, btrfs, ISO 9660, UDF -- not a libblkid passthrough.
Anything else (f2fs, minix, squashfs, ...) is reported as "no known
filesystem", which libblkid on the same host may well identify. That verdict
therefore collapses a legitimate but unlisted format and a medium carrying no
structure at all into one string, and must not carry policy weight.

The whole stage is also skippable by the device: the medium is read only if the
block node appears within the poll window, and how long that takes is partly up
to the device (a slow READ CAPACITY, medium-not-ready). A hostile device can
force the "judged on declared identity alone" path at will. The medium result
is context for the operator; the admission decision rests on stages 1-2.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It does not walk directories, read files, or look for autorun.inf and friends.
That would mean implementing FAT and NTFS parsing -- reintroducing exactly the
attack surface this stage exists to avoid, in a language that is safer but in
code far less reviewed than the kernel's. Content inspection at that depth
belongs in a sandbox, not in the admission path.
"""

from __future__ import annotations

import re as _re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from . import storage_hardening

SECTOR = 512
MBR_SIGNATURE = 0xAA55
GPT_SIGNATURE = b"EFI PART"
PROTECTIVE_MBR_TYPE = 0xEE

# How much we read. Enough for the MBR, the GPT header and its first entries,
# plus the start of the first partition to sniff a filesystem signature.
HEADER_READ = SECTOR * 34

# Per partition: enough to reach every signature sniff_filesystem() checks.
# One sector stopped short of the ext magic (0x438) and the btrfs magic
# (0x10040), so those filesystems were never recognised inside a partition.
# The same length is read for a partitionless medium, whose filesystem starts
# at LBA 0: HEADER_READ ends at 0x4400, before the ISO 9660 / UDF descriptors
# at 0x8000, so a raw-written live image read as "no known filesystem".
PARTITION_SNIFF_READ = SECTOR * 129       # 0x10200 >= 0x10048

# Optical-image filesystems (ISO 9660, UDF) leave the first 16 sectors of 2 KiB
# -- the "system area" -- to the medium, and begin their volume descriptors at
# byte 0x8000. Each descriptor is one 2 KiB sector: a type byte, then a
# five-byte standard identifier. ISO 9660 says "CD001"; UDF's Volume
# Recognition Sequence says "BEA01", then "NSR02"/"NSR03", then "TEA01".
OPTICAL_VD_START = 0x8000
OPTICAL_VD_STRIDE = 0x800
ISO9660_ID = b"CD001"
UDF_NSR_IDS = (b"NSR02", b"NSR03")

# A signature is five bytes anyone can write. ISO 9660 and UDF are only
# reported when the structure those bytes introduce is actually there, walked
# within a fixed bound: 16 descriptors of 2 KiB end at 0x10000, inside
# PARTITION_SNIFF_READ, so the check never reads further than the sniff did.
OPTICAL_MAX_DESCRIPTORS = 16
ISO_VD_BOOT, ISO_VD_PRIMARY, ISO_VD_SUPPLEMENTARY, ISO_VD_PARTITION = 0, 1, 2, 3
ISO_VD_TERMINATOR = 0xFF
# ECMA-119 6.2.2: a logical block is 2^(n+9) bytes and no larger than the
# 2048-byte logical sector, so 512, 1024 or 2048 -- never 4096.
ISO_BLOCK_SIZES = (512, 1024, 2048)
# ECMA-167 2/9.1: every descriptor in the Volume Recognition Sequence is
# structure type 0, version 1, and occupies max(2048, block size) bytes, so the
# sequence is walked at a 2 KiB and at a 4 KiB stride.
UDF_VRS_IDS = (ISO9660_ID, b"CDW02", b"BEA01", b"NSR02", b"NSR03",
               b"TEA01", b"BOOT2")
UDF_VRS_STRIDES = (0x800, 0x1000)

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
class GptEntry:
    """
    One used GPT partition entry: its type and attributes, nothing more.

    Read only for the media-change rules (EFI system partition, hidden
    partition). The geometry rules still judge the protective MBR entries, so
    what an entry claims about its own extent is not trusted here.
    """
    index: int
    type_guid: str
    attributes: int


@dataclass
class MediumReport:
    """What the raw medium says about itself."""
    device: str = ""
    size_sectors: Optional[int] = None
    scheme: str = "unknown"          # mbr / gpt / none
    partitions: List[Partition] = field(default_factory=list)
    # GPT partition entries found inside HEADER_READ. `gpt_entries_parsed` is
    # False when the header points its entry array anywhere else, so a rule
    # that found no EFI system partition can say it did not look.
    gpt_entries: List[GptEntry] = field(default_factory=list)
    gpt_entries_parsed: bool = False
    signatures: dict = field(default_factory=dict)  # partition index -> fs name
    suspicious: List[str] = field(default_factory=list)  # impossible/hostile partitions
    # A filesystem signature found WITHOUT the structure it introduces: where,
    # and why the structure was rejected. Such a signature is not reported as a
    # filesystem; rules.storage_findings turns these into a finding instead.
    hollow_signatures: List[str] = field(default_factory=list)
    # `error` is operator-facing: a short reason from a fixed vocabulary, shown
    # in the MEDIUM block and the "could not be read" finding. `detail` is the
    # raw diagnostic behind it (exception text, device paths) and goes to the
    # JSON audit log ONLY -- it is never rendered at the decision prompt.
    error: Optional[str] = None
    detail: Optional[str] = None
    timed_out: bool = False

    @property
    def inspected(self) -> bool:
        return self.error is None and self.scheme != "unknown"


# --------------------------------------------------------------------------
# Locating the block device
# --------------------------------------------------------------------------

# Whole disks only: sda, sdb, ... sdaa. NOT a partition (sda1), NOT an
# internal NVMe/MMC disk, NOT a mapper or loop device, and NOT anything with a
# path separator or a dot-dot in it.
#
# This mirrors gate_server._BLOCK_NAME deliberately. The gate refuses to open
# anything else, so a name outside this set could only ever produce a denied
# request under --privsep -- but the DIRECT backend has no such gate, and
# os.open("/dev/" + name) there is reached with `name` taken verbatim from a
# directory entry. The two halves must agree about what a whole USB disk is,
# and the agreement has to be enforced on both sides rather than on the one
# that happens to be looking.
_WHOLE_DISK_NAME = _re.compile(r"^sd[a-z]+$")


def find_block_devices(usb_syspath) -> List[str]:
    """
    Find /dev/sdX nodes belonging to one USB device.

    Walks the sysfs tree beneath the device looking for `block/<name>`, the
    same ancestry approach used for input nodes -- and for the same reason:
    inspecting the wrong disk would be considerably worse than inspecting none.

    THE FILTER IS NOT COSMETIC. The directory entry under `block/` was being
    concatenated straight into "/dev/{name}" and handed to os.open() in the
    direct (non-privsep) backend. Two things follow from that:

      * a name containing ../ escapes /dev entirely, so the "inspect only the
        medium you were handed" property rested on nothing but the kernel
        choosing tame names;
      * a partition node (sda1) or an internal disk name reaching this list is
        Probolos opening something it was never asked about -- read-only, but
        read-only access to a raw disk is still access to every byte on it.

    Restricting to whole sdX disks is the same rule gate_server._safe_block_path
    already enforces on the privileged side, applied here so both deployment
    modes behave identically instead of one of them relying on the other.
    """
    import os

    root = os.path.realpath(str(usb_syspath))
    found = []
    for dirpath, dirnames, _files in os.walk(root):
        if os.path.basename(dirpath) == "block":
            for name in dirnames:
                if _WHOLE_DISK_NAME.match(name):
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


# UEFI 2.x 5.3: the entry array normally starts at LBA 2 with 128-byte entries.
# Only that layout is read, and only as far as HEADER_READ already reaches (32
# sectors, 128 entries): no further read is issued at an offset the medium
# chose.
GPT_ENTRY_SIZE = 128
GPT_ENTRIES_LBA = 2
GPT_ESP_GUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
# Bit 62 of a basic-data entry's attributes: "hidden" to Windows.
GPT_ATTR_HIDDEN = 1 << 62


def parse_gpt_entries(data: bytes) -> Optional[List[GptEntry]]:
    """
    Used GPT entries from the header read, or None if they are not in it.

    Bounded by the bytes given, never by the header's own entry count: a count
    of 2^32 costs nothing here.
    """
    import uuid

    if len(data) < SECTOR * 2 or data[SECTOR:SECTOR + 8] != GPT_SIGNATURE:
        return None
    entries_lba, count, size = struct.unpack_from("<QII", data, SECTOR + 72)
    if entries_lba != GPT_ENTRIES_LBA or size != GPT_ENTRY_SIZE:
        return None
    start = GPT_ENTRIES_LBA * SECTOR
    available = max(0, (len(data) - start) // GPT_ENTRY_SIZE)
    found = []
    for i in range(min(count, available)):
        raw = data[start + i * GPT_ENTRY_SIZE:start + (i + 1) * GPT_ENTRY_SIZE]
        type_bytes = raw[:16]
        if type_bytes == bytes(16):
            continue                    # unused slot
        attributes = struct.unpack_from("<Q", raw, 48)[0]
        found.append(GptEntry(index=i,
                              type_guid=str(uuid.UUID(bytes_le=type_bytes)),
                              attributes=attributes))
    return found


def sniff_filesystem(data: bytes,
                     limit_bytes: Optional[int] = None) -> Optional[str]:
    """The filesystem identify_filesystem() finds, without its note."""
    return identify_filesystem(data, limit_bytes)[0]


def identify_filesystem(data: bytes, limit_bytes: Optional[int] = None
                        ) -> Tuple[Optional[str], Optional[str]]:
    """
    Identify a filesystem: (name, note).

    `name` is None when nothing is recognised. `note` is set when a signature
    WAS present but the structure behind it is not -- the case a planted magic
    produces -- and says why; the signature is then not reported as a
    filesystem. `limit_bytes` is how much device there is from `data`'s start,
    when known: a volume claiming more space than that does not fit on it.

    Signature matching only -- no structure is followed, no length inside the
    image is trusted. The point is to compare what the medium CLAIMS in its
    partition table against what is actually written there.
    """
    if len(data) < 512:
        return None, None
    if data[3:11] in (b"NTFS    ",):
        return "NTFS", None
    if data[3:11] == b"EXFAT   ":
        return "exFAT", None
    if data[54:59] == b"FAT12":
        return "FAT12", None
    if data[54:59] == b"FAT16":
        return "FAT16", None
    if data[82:87] == b"FAT32":
        return "FAT32", None
    if len(data) > 0x438 + 2:
        magic = struct.unpack_from("<H", data, 0x438)[0]
        if magic == 0xEF53:
            return "ext2/3/4", None
    # btrfs: the magic is 8 bytes at 0x10040 (superblock offset 0x10000 + 0x40).
    #
    # Two dead comparisons used to sit here. One sliced FOUR bytes and compared
    # them to an EIGHT-byte literal, so it could never be true; the other
    # compared a nine-byte slice to a four-byte literal, same result, and would
    # have returned None mid-chain even if it had matched. Both looked like
    # checks and were not -- the kind of thing that makes a signature list read
    # as more thorough than it is.
    #
    # Only reachable with a buffer that contains the btrfs superblock, which is
    # why inspect() reads PARTITION_SNIFF_READ bytes per partition.
    if len(data) >= 0x10048 and data[0x10040:0x10048] == b"_BHRfS_M":
        return "btrfs", None
    # Optical images: ISO 9660 and UDF, from sector 16 (0x8000). Checked after
    # every LBA-0 signature, because the 32 KiB system area in front of the
    # descriptors is the medium's to use: an isohybrid image keeps an MBR in
    # it, and a FAT boot sector there is what the medium is actually booted as.
    return _identify_optical(data, limit_bytes)


def _identify_optical(data: bytes, limit_bytes: Optional[int]
                      ) -> Tuple[Optional[str], Optional[str]]:
    """
    ISO 9660 / UDF, reported only when the volume structure checks out.

    THE MAGIC IS NOT THE FILESYSTEM
    -------------------------------
    This used to answer "ISO 9660" for the five bytes CD001 at 0x8001, and
    "UDF" for NSR02 anywhere in the area. Six bytes written to a blank stick
    made stage 4 show the operator a "whole-device ISO 9660 filesystem" -- the
    medium dictating its own label, in a tool whose premise is that the medium
    is hostile. Both are now walked as structures (see _iso9660_problem and
    _udf_vrs_problem). Nothing is followed outside the bytes already read, and
    no length the medium states is used to index anything.

    A UDF/ISO 9660 bridge image carries both and is reported as UDF, the
    structure a modern reader actually uses -- the same choice blkid makes.
    """
    if len(data) < OPTICAL_VD_START + 6:
        return None, None
    notes = []

    iso_ok = False
    if data[OPTICAL_VD_START + 1:OPTICAL_VD_START + 6] == ISO9660_ID:
        problem = _iso9660_problem(data, limit_bytes)
        iso_ok = problem is None
        if problem:
            notes.append(f"ISO 9660 signature at sector 16, but {problem}")

    udf_ok = False
    if _udf_nsr_present(data):
        problem = _udf_vrs_problem(data)
        udf_ok = problem is None
        if problem:
            notes.append(f"UDF signature present, but {problem}")

    if udf_ok:
        name = "UDF (ISO 9660 bridge)" if iso_ok else "UDF"
    elif iso_ok:
        name = "ISO 9660"
    else:
        name = None
    return name, ("; ".join(notes) or None)


def _both_endian(vd: bytes, offset: int, width: int) -> Optional[int]:
    """
    An ECMA-119 both-byte-order field: `width` bytes little-endian, then the
    same value big-endian. None when the two halves disagree -- which no
    mastering tool writes and a forger has to get right on purpose.
    """
    le = int.from_bytes(vd[offset:offset + width], "little")
    be = int.from_bytes(vd[offset + width:offset + 2 * width], "big")
    return le if le == be else None


def _iso9660_problem(data: bytes, limit_bytes: Optional[int]) -> Optional[str]:
    """
    Why this is not an ISO 9660 volume, or None if it is one (ECMA-119).

    1. The Volume Descriptor Set, walked from sector 16: every descriptor
       carries CD001 and a defined type and version, and the set ends in a
       Terminator within OPTICAL_MAX_DESCRIPTORS.
    2. A Primary Volume Descriptor is in it, and its both-byte-order fields
       agree with themselves: volume space size, volume set size and sequence
       number, logical block size, path table size.
    3. The PVD's root directory record is a directory record: 34 bytes, the
       directory flag set, an extent inside the volume.
    4. The volume fits on the device it is on.
    """
    pvd = None
    for index in range(OPTICAL_MAX_DESCRIPTORS):
        start = OPTICAL_VD_START + index * OPTICAL_VD_STRIDE
        vd = data[start:start + OPTICAL_VD_STRIDE]
        sector = 16 + index
        if len(vd) < OPTICAL_VD_STRIDE:
            return (f"the descriptor set is cut off at sector {sector} "
                    f"(end of device)")
        if vd[1:6] != ISO9660_ID:
            return f"sector {sector} ends the descriptor set without a terminator"
        vtype, version = vd[0], vd[6]
        if vtype == ISO_VD_TERMINATOR:
            if version != 1:
                return f"the terminator at sector {sector} has version {version}"
            break
        if vtype == ISO_VD_SUPPLEMENTARY:
            # 2 is the ISO 9660:1999 Enhanced Volume Descriptor.
            if version not in (1, 2):
                return f"descriptor at sector {sector} has version {version}"
        elif vtype in (ISO_VD_BOOT, ISO_VD_PRIMARY, ISO_VD_PARTITION):
            if version != 1:
                return f"descriptor at sector {sector} has version {version}"
            if vtype == ISO_VD_PRIMARY and pvd is None:
                pvd = vd
        else:
            return f"descriptor at sector {sector} has undefined type {vtype}"
    else:
        return (f"no set terminator within {OPTICAL_MAX_DESCRIPTORS} "
                f"descriptors")
    if pvd is None:
        return "the descriptor set has no primary volume descriptor"

    blocks = _both_endian(pvd, 80, 4)
    if not blocks:
        return "the volume space size is zero or its two encodings disagree"
    set_size = _both_endian(pvd, 120, 2)
    sequence = _both_endian(pvd, 124, 2)
    if not set_size or not sequence or sequence > set_size:
        return "the volume set size and sequence number are inconsistent"
    block_size = _both_endian(pvd, 128, 2)
    if block_size not in ISO_BLOCK_SIZES:
        return "the logical block size is invalid or its encodings disagree"
    if not _both_endian(pvd, 132, 4):
        return "the path table size is zero or its encodings disagree"

    root = pvd[156:190]
    extent = _both_endian(root, 2, 4)
    length = _both_endian(root, 10, 4)
    if (root[0] != 34 or not (root[25] & 0x02) or root[32] != 1
            or not extent or not length or extent >= blocks):
        return "the root directory record is not a valid directory record"
    if pvd[881] != 1:
        return "the file structure version is not 1"

    if limit_bytes is not None and blocks * block_size > limit_bytes:
        return (f"the volume claims {blocks * block_size} bytes where the "
                f"device has {limit_bytes}")
    return None


def _udf_nsr_present(data: bytes) -> bool:
    """An NSR02/NSR03 identifier anywhere in the recognition area."""
    end = min(len(data) - 5,
              OPTICAL_VD_START + OPTICAL_MAX_DESCRIPTORS * OPTICAL_VD_STRIDE)
    return any(data[off + 1:off + 6] in UDF_NSR_IDS
               for off in range(OPTICAL_VD_START, end, OPTICAL_VD_STRIDE))


def _udf_vrs_problem(data: bytes) -> Optional[str]:
    """
    Why this is not a UDF Volume Recognition Sequence, or None (ECMA-167).

    The sequence is consecutive descriptors from 0x8000, each structure type 0
    and version 1 (ISO 9660 descriptors excepted, which a bridge image puts
    first), ending at the first slot that is not a recognition descriptor. UDF
    requires BEA01, then NSR02 or NSR03, then TEA01, in that order. This is the
    check the kernel's udf_check_vsd() makes before looking any further; the
    anchor at sector 256 lies beyond what stage 4 reads and is not checked.
    """
    for stride in UDF_VRS_STRIDES:
        state = "start"
        for index in range(OPTICAL_MAX_DESCRIPTORS):
            off = OPTICAL_VD_START + index * stride
            ident = data[off + 1:off + 6]
            if len(ident) < 5 or ident not in UDF_VRS_IDS:
                break
            if ident != ISO9660_ID and (data[off] != 0 or data[off + 6] != 1):
                break
            if ident == b"BEA01" and state == "start":
                state = "extended"
            elif ident in UDF_NSR_IDS and state == "extended":
                state = "nsr"
            elif ident == b"TEA01" and state == "nsr":
                return None
        # fall through to the next stride
    return "no BEA01, NSR, TEA01 recognition sequence surrounds it"


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

    # fork, explicitly. The default start method on some setups is "spawn"
    # (or "forkserver"), which re-imports the whole probolos package in the
    # child on every single inspection -- seconds of latency, and worse, it
    # lengthens the window in which the device is authorized and udisks2 can
    # automount it. fork inherits the already-loaded interpreter and the open
    # fd directly, so the child is ready in microseconds.
    ctx = multiprocessing.get_context("fork")
    parent_conn, child_conn = ctx.Pipe()
    proc = ctx.Process(
        target=_inspect_worker, args=(device, child_conn, fd), daemon=True)
    try:
        proc.start()
        child_conn.close()
        proc.join(timeout)
        if proc.is_alive():
            proc.terminate()
            proc.join(1.0)
            if proc.is_alive():
                proc.kill()
                proc.join(0.1)
            # `inspected` stays False (scheme unknown), so no rule mistakes a
            # stalled device for one that passed. The silence is the finding.
            return MediumReport(
                device=device,
                error=f"device did not respond within {timeout:.0f}s -- "
                      f"inspection abandoned",
                timed_out=True)
        if parent_conn.poll():
            kind, payload = parent_conn.recv()
            return payload if kind == "ok" else MediumReport(device=device,
                                                             error=payload)
        return MediumReport(device=device,
                            error="inspection process produced no result")
    finally:
        parent_conn.close()
        child_conn.close()
        if proc.pid is not None and not proc.is_alive():
            proc.close()
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

    ONE DESCRIPTOR, OPENED ONCE (bug fix)
    -------------------------------------
    This function used to open, read the header, and CLOSE -- then call
    _read_at() per partition, which opened again through the same open_fn. That
    is wrong in two separate ways, and both were silent:

      * Under --privsep (and inside inspect_safely's fork worker) open_fn is
        `lambda _dev: fd`, a closure over ONE already-open descriptor. The
        second call handed back the same integer, which had just been closed,
        so every per-partition read failed with EBADF and returned b"". The
        filesystem-signature check -- the whole point of stage 4's second half,
        and the input to the "partition contains something other than it
        declares" rule -- therefore never ran on the privileged path. It failed
        by returning nothing, which reads exactly like a clean medium.

      * A closed descriptor number is immediately reusable. If anything else in
        the process opened a file between the close and the next _read_at, that
        file's bytes would be lseek'd into and fed to sniff_filesystem as if
        they came from the device. Wrong answers from the wrong file is a worse
        failure than no answer.

    So: acquire the descriptor once, read everything from it with os.pread
    (which takes an offset and does not disturb the file position, removing the
    lseek entirely), and close it once at the end.
    """
    import os

    report = MediumReport(device=device)
    report.size_sectors = read_size_sectors(device)

    # HARDENING (1/3): the declared size is itself device-controlled, and every
    # per-partition bounds check below is measured against it. An absurd size
    # therefore does not just produce a wrong number -- it silently disables the
    # checks that depend on it. So it is validated first, and a size that fails
    # is discarded rather than trusted, which falls back to the absolute limits
    # in validate_partition() instead of a device-supplied one.
    size_ok, size_reason = storage_hardening.device_size_sane(report.size_sectors)
    if not size_ok:
        report.suspicious.append(f"declared device size rejected: {size_reason}")
        report.size_sectors = None

    fd = None
    try:
        try:
            fd = open_fn(device) if open_fn else os.open(device, os.O_RDONLY)
            data = os.pread(fd, HEADER_READ, 0)
        except OSError as exc:
            report.error = str(exc)
            return report

        if len(data) < SECTOR:
            report.error = f"only {len(data)} bytes readable"
            return report

        partitions = parse_mbr(data)
        gpt = parse_gpt_header(data)

        if gpt is not None:
            report.scheme = "gpt"
            report.partitions = partitions      # the protective MBR entries
            entries = parse_gpt_entries(data)
            if entries is not None:
                report.gpt_entries = entries
                report.gpt_entries_parsed = True
        elif partitions:
            report.scheme = "mbr"
            report.partitions = partitions
        else:
            # No partition table. Common and legitimate: many USB sticks are
            # formatted as a "superfloppy", with a filesystem written directly
            # to the medium, and every dd-written live image (Slax, Tails, any
            # isohybrid) is an ISO 9660 filesystem starting at LBA 0. Sniff it
            # so this is reported as a fact, not an anomaly.
            #
            # The header read stops at 0x4400, short of the optical-image
            # descriptors at 0x8000 and the btrfs magic at 0x10040, so the
            # medium is read again over the same descriptor for as far as a
            # partition would be. Reporting a whole operating system as "no
            # known filesystem" reads as a blank stick -- the opposite of the
            # truth, and the medium an operator is most likely to wave through.
            # A short or failed read simply means "signature absent".
            report.scheme = "none"
            chunk = _read_at(fd, 0, PARTITION_SNIFF_READ)
            limit = (report.size_sectors * SECTOR
                     if report.size_sectors else None)
            fs, note = identify_filesystem(
                chunk if len(chunk) > len(data) else data, limit)
            if fs:
                report.signatures[-1] = fs
            if note:
                report.hollow_signatures.append(f"whole device: {note}")
            return report

        # HARDENING (2/3): split the table into partitions that can be read and
        # partitions that cannot, BEFORE touching the medium again. Doing it up
        # front means the whole geometry is judged as a unit and every
        # rejection is reported with its reason -- previously the per-partition
        # guard below rejected on offset alone, so a partition with a sane
        # start and an absurd LENGTH was read anyway and its impossibility
        # never surfaced.
        readable, impossible = storage_hardening.filter_safe_partitions(
            report.partitions, report.size_sectors)
        report.suspicious.extend(impossible)

        # Read the first sector of each partition to see what is actually
        # there.
        for part in readable:
            if part.type_byte == PROTECTIVE_MBR_TYPE:
                continue
            # HARDENING (3/3): never read at a device-controlled offset without
            # checking it fits inside the real device first. A partition
            # claiming start_lba=0xFFFFFFFF would otherwise reach for ~2 TB.
            # Kept even though filter_safe_partitions has already vetted this
            # one: it is the guard immediately above the read, and a guard that
            # lives anywhere else is one refactor away from not running.
            offset = storage_hardening.safe_read_offset(
                part.start_lba, report.size_sectors)
            if offset is None:
                report.suspicious.append(
                    f'partition {part.index}: start_lba {part.start_lba} '
                    f'does not fit the device; not read')
                continue
            chunk = _read_at(fd, offset, PARTITION_SNIFF_READ)
            if chunk:
                # Bounded by the end of the DEVICE, not of the partition: the
                # partition length is the medium's own claim, the device size
                # is not.
                limit = ((report.size_sectors - part.start_lba) * SECTOR
                         if report.size_sectors else None)
                fs, note = identify_filesystem(chunk, limit)
                if fs:
                    report.signatures[part.index] = fs
                if note:
                    report.hollow_signatures.append(
                        f"partition {part.index + 1}: {note}")

        return report
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _read_at(fd: int, offset: int, length: int) -> bytes:
    """
    One bounded read at an offset on an ALREADY-OPEN descriptor.

    pread rather than lseek+read: it carries the offset with the call, so there
    is no file position to leave behind and no window in which a concurrent
    reader could move it. Failures are silent and non-fatal -- a partition that
    will not read is reported by its absence from `signatures`, not by killing
    the whole inspection.
    """
    import os

    try:
        return os.pread(fd, length, offset)
    except OSError:
        return b""


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
