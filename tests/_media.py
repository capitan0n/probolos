"""
Minimal, structurally valid optical-image headers for stage-4 tests.

A bare CD001 or NSR02 is now correctly refused as a forgery, so tests that mean
"a real ISO 9660 / UDF volume" build one here: the descriptors a mastering tool
writes from sector 16, with every both-byte-order field consistent. Only the
bytes stage 4 reads are produced; there are no files behind the root record.
"""

from __future__ import annotations

ISO_START = 0x8000
VD = 0x800


def _both(value: int, width: int) -> bytes:
    return value.to_bytes(width, "little") + value.to_bytes(width, "big")


def primary_volume_descriptor(volume_blocks: int = 64,
                              block_size: int = 2048) -> bytearray:
    pvd = bytearray(VD)
    pvd[0:7] = b"\x01CD001\x01"
    pvd[8:40] = b"LINUX".ljust(32)
    pvd[40:72] = b"SLAX".ljust(32)
    pvd[80:88] = _both(volume_blocks, 4)
    pvd[120:124] = _both(1, 2)               # volume set size
    pvd[124:128] = _both(1, 2)               # volume sequence number
    pvd[128:132] = _both(block_size, 2)
    pvd[132:140] = _both(10, 4)              # path table size
    pvd[140:144] = (19).to_bytes(4, "little")
    pvd[148:152] = (20).to_bytes(4, "big")
    root = bytearray(34)
    root[0] = 34
    root[2:10] = _both(21, 4)                # extent
    root[10:18] = _both(2048, 4)             # data length
    root[25] = 0x02                          # directory
    root[28:32] = _both(1, 2)
    root[32] = 1
    pvd[156:190] = root
    pvd[881] = 1                             # file structure version
    return pvd


def descriptor(vtype: int, ident: bytes, version: int = 1) -> bytearray:
    vd = bytearray(VD)
    vd[0] = vtype
    vd[1:6] = ident
    vd[6] = version
    return vd


def iso9660_descriptors(volume_blocks: int = 64, block_size: int = 2048,
                        before=(), after=()) -> bytes:
    """Sector 16 onward: [before...] PVD [after...] terminator."""
    parts = list(before) + [primary_volume_descriptor(volume_blocks,
                                                      block_size)]
    parts += list(after) + [descriptor(0xFF, b"CD001")]
    return b"".join(bytes(p) for p in parts)


def udf_vrs(stride: int = VD, nsr: bytes = b"NSR02") -> bytes:
    """BEA01, NSR, TEA01 at the given stride."""
    out = bytearray()
    for ident in (b"BEA01", nsr, b"TEA01"):
        slot = bytearray(stride)
        slot[0:7] = b"\x00" + ident + b"\x01"
        out += slot
    return bytes(out)


def image(size: int = 128 * 1024, at: int = ISO_START, *chunks: bytes
          ) -> bytearray:
    """A zeroed device with `chunks` written back to back from `at`."""
    data = bytearray(size)
    for chunk in chunks:
        data[at:at + len(chunk)] = chunk
        at += len(chunk)
    return data


def iso9660_image(size: int = 128 * 1024, **kwargs) -> bytearray:
    return image(size, ISO_START, iso9660_descriptors(**kwargs))
