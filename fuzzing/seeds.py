"""
Synthetic seeds, one list per seed group (see targets.SEED_GROUP).

Mutation-based fuzzing only reaches deep code if it starts from inputs that
already get past the first checks. Real devices are better seeds (see
build_corpus.py); these are always added to whatever the corpus holds, built
from the project's own test fixtures and testbed presets so they stay in step
with what the parsers accept.
"""
from __future__ import annotations

import json
import struct
from dataclasses import asdict
from functools import lru_cache


def _blob(*interfaces, vid=0x0951, pid=0x1666):
    from tests._support import descriptor_blob
    return descriptor_blob(*interfaces, vid=vid, pid=pid)


@lru_cache(maxsize=None)
def descriptor_seeds():
    seeds = [
        _blob((0x08, 0x06, 0x50)),                          # USB stick
        _blob((0x03, 0x01, 0x01), (0x03, 0x00, 0x00)),      # keyboard
        _blob((0x03, 0x01, 0x02)),                          # mouse
        _blob((0x08, 0x06, 0x50), (0x03, 0x00, 0x00)),      # stick + HID
        _blob((0xFF, 0x42, 0x01), (0x02, 0x02, 0x01),       # vendor + CDC
              (0x0A, 0x00, 0x00)),
        _blob((0x0E, 0x01, 0x00), (0x0E, 0x02, 0x00),       # camera + audio
              (0x01, 0x01, 0x00), (0x01, 0x02, 0x00)),
        _blob((0xE0, 0x01, 0x01), (0xE0, 0x01, 0x01)),      # bluetooth
    ]
    try:
        from testbed import spawn
    except ImportError:                  # optional extras
        spawn = None
    if spawn is not None:
        seeds += [make().full_descriptors_blob()
                  for make in spawn.PRESETS.values()]
    # A device with an HID class descriptor, endpoints, an IAD and a BOS-ish
    # tail: types the parser must skip rather than understand.
    hid = (bytes([18, 1]) + struct.pack("<H", 0x0200) + bytes([0, 0, 0, 64])
           + struct.pack("<HHH", 0x046D, 0xC52B, 0x1201) + bytes([1, 2, 0, 1]))
    body = (bytes([8, 0x0B, 0, 2, 3, 1, 1, 0])              # IAD
            + bytes([9, 4, 0, 0, 1, 3, 1, 1, 0])
            + bytes([9, 0x21, 0x11, 0x01, 0, 1, 0x22, 63, 0])
            + bytes([7, 5, 0x81, 3, 8, 0, 10])
            + bytes([9, 4, 1, 0, 1, 3, 0, 2, 0])
            + bytes([9, 0x21, 0x11, 0x01, 0, 1, 0x22, 52, 0])
            + bytes([7, 5, 0x82, 3, 8, 0, 10]))
    cfg = bytes([9, 2]) + struct.pack("<H", 9 + len(body)) + bytes(
        [2, 1, 0, 0xA0, 49])
    seeds.append(hid + cfg + body)
    return seeds


# Boot keyboard and mouse report descriptors (HID 1.11 appendix B), plus
# PUSH/POP and a long item, the parts walk_hid_items bounds explicitly.
_KEYBOARD_REPORT = bytes.fromhex(
    "05010906a101050719e029e71500250175019508810295017508810195057501"
    "050819012905910295017503910195067508150025650507190029658100c0")
_MOUSE_REPORT = bytes.fromhex(
    "05010902a1010901a100050919012903150025019503750181029501750581"
    "0105010930093115812581267f750895028106c0c0")


@lru_cache(maxsize=None)
def hid_seeds():
    return [
        _KEYBOARD_REPORT,
        _MOUSE_REPORT,
        bytes.fromhex("a4a4a4b4b4b405010906a101c0"),
        bytes.fromhex("fe0201aabb05010906a101750896ff0f8102c0"),
        bytes.fromhex("0601ff0901a101150026ff0075089640008102"
                      "09029640009102c0"),
    ]


def _mbr(entries, size_sectors=2048):
    data = bytearray(size_sectors * 512)
    for slot, (boot, ptype, start, count) in enumerate(entries):
        struct.pack_into("<BBBBBBBBII", data, 446 + 16 * slot,
                         boot, 0, 0, 0, ptype, 0, 0, 0, start, count)
    data[510:512] = b"\x55\xaa"
    return data


def _fat32_boot(data, lba):
    off = lba * 512
    data[off:off + 3] = b"\xeb\x58\x90"
    data[off + 3:off + 11] = b"MSDOS5.0"
    struct.pack_into("<HBH", data, off + 11, 512, 8, 32)
    data[off + 82:off + 90] = b"FAT32   "
    data[off + 510:off + 512] = b"\x55\xaa"


@lru_cache(maxsize=None)
def disk_seeds():
    from tests import _media
    seeds = []
    # FAT32 stick: one partition at 2048, filesystem where it says.
    d = _mbr([(0x80, 0x0C, 64, 4000)], 256)
    _fat32_boot(d, 64)
    seeds.append(bytes(d))
    # Linux + NTFS, and an extended partition.
    d = _mbr([(0, 0x83, 64, 64), (0, 0x07, 128, 64), (0, 0x05, 192, 32)], 256)
    d[64 * 512 + 0x438:64 * 512 + 0x43A] = b"\x53\xef"
    d[128 * 512 + 3:128 * 512 + 11] = b"NTFS    "
    seeds.append(bytes(d))
    # Protective MBR + GPT header + two entries (ESP, basic data).
    d = _mbr([(0, 0xEE, 1, 0xFFFFFFFF)], 160)
    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", hdr, 8, 0x00010000, 92, 0, 0, 1, 159, 34,
                     126)
    struct.pack_into("<QII", hdr, 72, 2, 128, 128)
    d[512:604] = hdr
    esp = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
    basic = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")
    for i, (guid, first, last) in enumerate(((esp, 34, 80), (basic, 81, 150))):
        e = 1024 + i * 128
        d[e:e + 16] = guid
        d[e + 16:e + 32] = bytes(range(i, i + 16))
        struct.pack_into("<QQQ", d, e + 32, first, last, 0)
        d[e + 56:e + 56 + 8] = "DATA".encode("utf-16-le")
    seeds.append(bytes(d))
    # Optical: ISO 9660 and UDF volume recognition sequences.
    seeds.append(bytes(_media.iso9660_image(96 * 1024)))
    seeds.append(bytes(_media.image(96 * 1024, _media.ISO_START,
                                    _media.udf_vrs())))
    seeds.append(bytes(_media.image(
        96 * 1024, _media.ISO_START,
        _media.iso9660_descriptors(), _media.udf_vrs(nsr=b"NSR03"))))
    # A bare superfloppy FAT (no partition table).
    d = bytearray(64 * 512)
    _fat32_boot(d, 0)
    seeds.append(bytes(d))
    return seeds


@lru_cache(maxsize=None)
def protocol_seeds():
    from probolos import protocol
    reqs = [
        protocol.Request(protocol.REQ_PING),
        protocol.Request(protocol.REQ_AUTHORIZE,
                         path="/sys/devices/pci0000:00/0000:00:14.0/usb1/1-4",
                         value=1, instance=(1, 1000)),
        protocol.Request(protocol.REQ_SET_DEFAULT,
                         path="/sys/devices/pci0000:00/0000:00:14.0/usb1",
                         value=0),
        protocol.Request(protocol.REQ_OPEN_INPUT, path="/dev/input/event7",
                         instance=(1, 1000)),
        protocol.Request(protocol.REQ_OPEN_BLOCK, path="/dev/sdb",
                         instance=(1, 1000)),
        protocol.Request(protocol.REQ_AUTHORIZE_INTERFACE,
                         path="/sys/devices/pci0000:00/0000:00:14.0/usb1/"
                              "1-4/1-4:1.0", value=1, instance=(1, 1000)),
        protocol.Request(protocol.REQ_TRUST,
                         path="/sys/devices/pci0000:00/0000:00:14.0/usb1/1-4",
                         instance=(1, 1000), key="0951:1666:AABB",
                         label="Kingston DataTraveler"),
    ]
    seeds = [r.encode() for r in reqs]
    seeds += [protocol.Response(s, d).encode() for s, d in
              ((protocol.OK, ""), (protocol.ERROR, "bad request"),
               (protocol.DENIED, "not blocked"))]
    return seeds


def path_seeds():
    return [p.encode() for p in (
        "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-4",
        "/sys/bus/usb/devices/1-4", "/sys/devices/../../etc/passwd",
        "/dev/input/event3", "/dev/input/../sda", "/dev/sdb", "/dev/sdb1",
        "/dev/nvme0n1", "/proc/self/root/dev/sda", "relative/1-4", "")]


def agent_seeds():
    msgs = [
        {"type": "hello", "version": 1},
        {"type": "answer", "id": 7, "answer": "yes"},
        {"type": "answer", "id": 7, "answer": "always"},
        {"type": "answer", "id": 8, "answer": "no"},
        {"type": "decide", "id": 7, "title": "Kingston DataTraveler",
         "body": "USB stick, no warnings", "severity": "INFO",
         "allow_always": True, "timeout": 60, "steps": "one",
         "capabilities": ["storage"]},
        {"type": "decide", "id": 9, "title": "Keyboard + storage",
         "body": "CRITICAL", "severity": "CRITICAL", "allow_always": False,
         "timeout": 600, "steps": "countdown", "countdown": 10,
         "note": "type the word"},
        {"type": "critical", "id": 3, "title": "x", "body": "y"},
        {"type": "notice", "title": "still blocked", "body": "replug it"},
        {"type": "cancel", "id": 7},
    ]
    return [json.dumps(m).encode() for m in msgs]


def ledger_seeds():
    from pathlib import Path
    from probolos import ledger
    from targets import _device
    led = ledger.Ledger(Path("/nonexistent/ledger.json"))
    for i, blob in enumerate(descriptor_seeds()[:4]):
        dev = _device(blob, "Kingston", "DataTraveler", f"S{i}")
        led.record(dev, "allowed", approved=True)
        led.record(dev, "user rejected")
    entries = {k: asdict(v) for k, v in led.entries.items()}
    full = {"schema": ledger.SCHEMA_VERSION,
            "fingerprint_scheme": "normalized-v1", "entries": entries,
            "media": {"0951:1666:S0#lun0": ["abc", "def"]}}
    return [json.dumps(full).encode(),
            json.dumps({"schema": 1, "entries": entries}).encode(),
            b'{"schema": 1}', b"{}", b"[]", b"null"]


def trust_seeds():
    from pathlib import Path
    from probolos import trust
    from targets import _device
    store = trust.TrustStore.__new__(trust.TrustStore)
    store.path = Path("/nonexistent/trusted.json")
    store.owners = None
    store.devices = {}
    store.load_error = None
    store._disk_sig = None
    out = {}
    for i, blob in enumerate(descriptor_seeds()[:4]):
        dev = _device(blob, "Kingston", "DataTraveler", f"S{i}")
        try:
            entry = store.trust(dev, note="fuzz")
        except Exception:                # noqa: BLE001
            entry = None
        if entry is not None:
            out[entry.key] = asdict(entry)
    return [json.dumps({"schema": trust.SCHEMA_VERSION,
                        "devices": out}).encode(),
            b'{"schema": 1, "devices": {}}', b"{}"]


def text_seeds():
    # First byte: limit (and bit 7: pass as bytes).
    return [b"\x7e" + "Kingston DataTraveler 3.0".encode(),
            b"\x20" + "Logitech‮USB Receiver".encode(),
            b"\xfe" + b"\x1b[2J\xff\xfe broken \xc3",
            b"\x10" + "Á̂̃̄﻿́".encode(),
            b"\x7e" + ("中" * 40 + "\U0001f600").encode()]


def payload_seeds():
    # [max_chars] then 3-byte events: code low byte, (value<<2)|code high.
    def ev(code, value):
        return bytes([code & 0xFF, ((value % 3) << 2) | (code >> 8)])
    def key(code):
        return ev(code, 1) + b"\x00" + ev(code, 0) + b"\x00"
    gui_r = ev(125, 1) + b"\x00" + key(19)[:-1] + b"\x00" + ev(125, 0) + b"\x00"
    typed = b"".join(key(c) for c in (35, 18, 38, 38, 24, 28))   # hello\n
    return [b"\x40" + gui_r + typed, b"\x08" + typed * 10,
            b"\xff" + ev(42, 1) + b"\x00" + typed + ev(42, 0) + b"\x00"]


GENERATORS = {
    "descriptors": descriptor_seeds, "hid": hid_seeds, "disk": disk_seeds,
    "protocol": protocol_seeds, "paths": path_seeds, "agent": agent_seeds,
    "ledger": ledger_seeds, "trust": trust_seeds, "text": text_seeds,
    "payload": payload_seeds,
}


def for_group(group: str):
    return list(GENERATORS[group]())
