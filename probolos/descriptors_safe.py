"""
descriptors_safe.py — Defensive layer for USB descriptor parsing in Probolos.

Design principle: every parsing error is a *finding*, not a crash.
A device that produces an error stays at authorized=0.

This file is self-contained (stdlib only) and does NOT replace descriptors.py.
The existing descriptors.py calls the primitives here (take/walk_descriptors)
instead of doing raw slicing.

WHY IT IS NEEDED, even though Python is memory-safe:
  1. Python slicing does NOT raise IndexError past the end — it silently
     returns a shorter bytes object. You then keep working with incomplete
     data thinking everything went fine. That is worse than a crash.
  2. bLength == 0 in a TLV chain => the pointer never advances => infinite
     loop. That is the real DoS, not IndexError.
  3. Declared lengths (wTotalLength) that do not match the actual buffer.
"""

from __future__ import annotations

from typing import Iterator, Tuple

# --------------------------------------------------------------------------
# Limits. Conservative but well above any legitimate device.
# --------------------------------------------------------------------------
MAX_DESCRIPTOR_ITEMS = 256      # number of descriptors in one configuration
MAX_HID_ITEMS = 4096            # number of items in a HID report descriptor
MAX_HID_PUSH_DEPTH = 16         # PUSH/POP stack depth (spec sets no limit)
MAX_HID_COLLECTION_DEPTH = 32   # depth of nested Collections
MAX_REPORT_BITS = 64 * 1024     # ReportCount * ReportSize per Main item


class DescriptorParsingError(ValueError):
    """Invalid data from the device.

    Inherits from ValueError so existing `except ValueError` catches it, but is
    semantically distinct: "the device lied", not "a bug in our code".

    `recoverable` separates two kinds of lie, and the distinction is load
    bearing now that descriptors.parse() walks through here:

      recoverable=True   the chain simply STOPS early -- a descriptor overruns
                         the buffer, or a lone header byte is left at the end.
                         Everything already parsed is still valid, so the caller
                         may keep it and record the truncation as a finding.

      recoverable=False  the chain cannot be walked at all -- bLength < 2 (the
                         offset would never advance) or an item flood. There is
                         no safe way to continue, so the caller must refuse the
                         device outright.

    Without this split, wiring the safe walker into the real parser would have
    turned "truncated tail, keep what we have" into "reject the device", which
    is a false positive on genuinely buggy but harmless hardware.
    """

    def __init__(self, message: str, recoverable: bool = False):
        super().__init__(message)
        self.recoverable = recoverable


# --------------------------------------------------------------------------
# 1. Safe byte access
# --------------------------------------------------------------------------
def take(buf: bytes, off: int, length: int, what: str) -> bytes:
    """Slicing that fails loudly instead of silently.

    Use it EVERYWHERE instead of buf[a:b] when a,b come — even indirectly —
    from the device.
    """
    if off < 0 or length < 0:
        raise DescriptorParsingError(f"{what}: negative offset/length")
    end = off + length
    if end > len(buf):
        raise DescriptorParsingError(
            f"{what}: asked for {length}B at offset {off}, "
            f"only {len(buf)}B available"
        )
    return buf[off:end]


def u8(buf: bytes, off: int, what: str) -> int:
    return take(buf, off, 1, what)[0]


def u16le(buf: bytes, off: int, what: str) -> int:
    """USB: all multi-byte fields are little-endian."""
    return int.from_bytes(take(buf, off, 2, what), "little")


# --------------------------------------------------------------------------
# 2. Walking the standard TLV chain
# --------------------------------------------------------------------------
def walk_descriptors(buf: bytes,
                     max_items: int = MAX_DESCRIPTOR_ITEMS
                     ) -> Iterator[Tuple[int, bytes]]:
    """Walks the format [bLength][bDescriptorType][payload...].

    Yields (bDescriptorType, whole_descriptor_as_bytes).

    The loop terminates PROVABLY: off advances by b_length, which is checked
    to be >= 2 before use. Without that check, a bLength=0 from a hostile
    device freezes the daemon forever.
    """
    off = 0
    seen = 0
    total = len(buf)

    while off < total:
        if seen >= max_items:
            raise DescriptorParsingError(
                f"more than {max_items} descriptors — possible exhaustion attempt"
            )
        if off + 2 > total:
            # One byte left: truncated chain. Recoverable -- the descriptors
            # before it parsed fine and the stray byte carries no meaning.
            raise DescriptorParsingError(
                f"truncated descriptor header at offset {off}",
                recoverable=True,
            )

        b_length = buf[off]
        b_type = buf[off + 1]

        if b_length < 2:
            # THE CRITICAL POINT. Every legitimate descriptor has at least
            # bLength + bDescriptorType = 2 bytes. NOT recoverable: the walk
            # cannot advance past this point by any amount, so "keep going" is
            # not an option that exists.
            raise DescriptorParsingError(
                f"bLength={b_length} at offset {off} — invalid (minimum 2)"
            )
        if off + b_length > total:
            # A descriptor that claims more bytes than were delivered. The tail
            # is unusable but the head is not, so this is recoverable.
            raise DescriptorParsingError(
                f"descriptor type 0x{b_type:02x} at offset {off} declares "
                f"{b_length}B but the buffer ends at {total}B",
                recoverable=True,
            )

        yield b_type, buf[off:off + b_length]

        off += b_length   # guaranteed >= 2
        seen += 1


def effective_total_length(cfg_buf: bytes) -> int:
    """wTotalLength of the Configuration Descriptor, clamped to reality.

    A hostile device declares wTotalLength=65535 while sending 40 bytes.
    The rule: trust the buffer size, not the declaration. The mismatch is not
    malicious on its own (buggy devices exist), so we return it as information
    rather than raising.
    """
    if len(cfg_buf) < 4:
        raise DescriptorParsingError("Configuration Descriptor < 4 bytes")
    declared = u16le(cfg_buf, 2, "wTotalLength")
    return min(declared, len(cfg_buf))


def wtotallength_mismatch(cfg_buf: bytes) -> int:
    """Returns declared - actual. Non-zero => worth recording as a finding."""
    declared = u16le(cfg_buf, 2, "wTotalLength")
    return declared - len(cfg_buf)


# --------------------------------------------------------------------------
# 3. HID Report Descriptors
# --------------------------------------------------------------------------
# CORRECTING THE REVIEW: HID report descriptors are NOT recursive. They are a
# flat stream of items. Two distinct notions of "depth" exist:
#   a) the PUSH/POP stack (Global items 0xA4 / 0xB4) — saves global state
#   b) Collection / End Collection nesting (Main items) — logical structure
# Both need a limit, each for a different reason.

HID_LONG_ITEM_PREFIX = 0xFE

# bType
_HID_TYPE_MAIN = 0
_HID_TYPE_GLOBAL = 1
_HID_TYPE_LOCAL = 2

# bTag (Main)
_TAG_COLLECTION = 0x0A
_TAG_END_COLLECTION = 0x0C
_MAIN_DATA_TAGS = (0x08, 0x09, 0x0B)      # Input, Output, Feature

# bTag (Global)
_TAG_REPORT_SIZE = 0x07
_TAG_REPORT_COUNT = 0x09
_TAG_PUSH = 0x0A
_TAG_POP = 0x0B


def walk_hid_items(buf: bytes,
                   max_items: int = MAX_HID_ITEMS,
                   max_push_depth: int = MAX_HID_PUSH_DEPTH,
                   max_collection_depth: int = MAX_HID_COLLECTION_DEPTH
                   ) -> Iterator[Tuple[int, int, bytes]]:
    """Walks HID items. Yields (bType, bTag, data_bytes).

    Short item format: one prefix byte
        bits 0-1  bSize  -> 0,1,2,4 bytes of data (the value 3 means 4!)
        bits 2-3  bType
        bits 4-7  bTag
    Long item format: prefix 0xFE, then bDataSize, bLongItemTag, data.

    Enforces simultaneously:
      - item count limit
      - PUSH/POP depth
      - Collection depth (and End Collection without a matching open)
      - a logical limit on ReportCount * ReportSize
    """
    off = 0
    seen = 0
    total = len(buf)

    push_depth = 0
    collection_depth = 0
    report_size = 0
    report_count = 0

    while off < total:
        if seen >= max_items:
            raise DescriptorParsingError(
                f"more than {max_items} HID items — possible exhaustion attempt"
            )

        prefix = buf[off]

        if prefix == HID_LONG_ITEM_PREFIX:
            # Long items are not used in practice; we read them correctly so
            # the alignment of the rest of the stream is not broken.
            if off + 3 > total:
                raise DescriptorParsingError("truncated HID long item")
            data_size = buf[off + 1]
            long_tag = buf[off + 2]
            data = take(buf, off + 3, data_size, "HID long item data")
            yield (-1, long_tag, data)
            off += 3 + data_size
            seen += 1
            continue

        b_size_code = prefix & 0x03
        b_size = 4 if b_size_code == 3 else b_size_code   # 3 -> 4 bytes
        b_type = (prefix >> 2) & 0x03
        b_tag = (prefix >> 4) & 0x0F

        data = take(buf, off + 1, b_size, f"HID item tag=0x{b_tag:x}")
        value = int.from_bytes(data, "little") if data else 0

        # --- state checks ---
        if b_type == _HID_TYPE_GLOBAL:
            if b_tag == _TAG_PUSH:
                push_depth += 1
                if push_depth > max_push_depth:
                    raise DescriptorParsingError(
                        f"HID PUSH depth {push_depth} > {max_push_depth}"
                    )
            elif b_tag == _TAG_POP:
                if push_depth == 0:
                    raise DescriptorParsingError("HID POP without a matching PUSH")
                push_depth -= 1
            elif b_tag == _TAG_REPORT_SIZE:
                report_size = value
            elif b_tag == _TAG_REPORT_COUNT:
                report_count = value

        elif b_type == _HID_TYPE_MAIN:
            if b_tag == _TAG_COLLECTION:
                collection_depth += 1
                if collection_depth > max_collection_depth:
                    raise DescriptorParsingError(
                        f"HID Collection depth {collection_depth} "
                        f"> {max_collection_depth}"
                    )
            elif b_tag == _TAG_END_COLLECTION:
                if collection_depth == 0:
                    raise DescriptorParsingError(
                        "HID End Collection without an open Collection"
                    )
                collection_depth -= 1
            elif b_tag in _MAIN_DATA_TAGS:
                # ReportCount=65535 * ReportSize=32 => a 2 Mbit "report".
                # No legitimate device does this; it is classic exhaustion.
                bits = report_size * report_count
                if bits > MAX_REPORT_BITS:
                    raise DescriptorParsingError(
                        f"declared report {report_count}x{report_size}b "
                        f"= {bits} bits — unrealistic"
                    )

        yield (b_type, b_tag, data)

        off += 1 + b_size   # guaranteed >= 1
        seen += 1

    if collection_depth != 0:
        raise DescriptorParsingError(
            f"{collection_depth} Collection(s) without End Collection"
        )
    if push_depth != 0:
        raise DescriptorParsingError(f"{push_depth} PUSH without POP")


# --------------------------------------------------------------------------
# 4. Fail-closed wrapper
# --------------------------------------------------------------------------
def safe_parse(fn, *args, **kwargs):
    """Runs a parsing function and turns the error into a value.

    Returns (result, error_message | None).

    Use in the analyzer:

        parsed, err = safe_parse(parse_configuration, raw)
        if err:
            findings.append(Finding(severity=CRITICAL,
                                    code="DESC_MALFORMED",
                                    detail=err))
            # the device stays at authorized=0

    We also catch bare Exception: an unexpected bug in the parser must not be
    allowed to bring down the daemon and leave the gate in an unknown state.
    A CRITICAL finding is always the safe answer.
    """
    try:
        return fn(*args, **kwargs), None
    except DescriptorParsingError as e:
        return None, str(e)
    except Exception as e:  # noqa: BLE001 — deliberately broad, fail-closed
        return None, f"{type(e).__name__} during parsing: {e}"
