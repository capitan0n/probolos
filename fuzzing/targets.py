"""
Fuzz targets for Probolos, shared by heavy_fuzz.py and fuzz_atheris.py.

Each target is `fn(data: bytes) -> None`. It catches ONLY the error the
production caller catches (the documented "refuse cleanly" exception), and
asserts the invariant the caller relies on. Anything else escaping is a
finding: in the daemon it is either a crash or a check that silently did not
run.

Every target names a seed group (`SEED_GROUP`): targets that read the same
kind of input share seeds -- see seeds.py and build_corpus.py.
"""
from __future__ import annotations

import atexit
import json
import os
import shutil
import struct
import tempfile
import unicodedata
import zlib
from pathlib import Path
from unittest import mock

from probolos import (agent as agent_mod, agentlink, analyzers, daemon,
                      descriptors, descriptors_safe, gate_server,
                      ledger as ledger_mod, payload, protocol, report, rules,
                      storage, storage_hardening, sysfs, textsafe, trust)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _text(data: bytes) -> str:
    """Bytes -> str that can carry lone surrogates and every code point."""
    return data.decode("utf-8", errors="surrogateescape")


def _forbidden(char: str) -> bool:
    """What cleaned text must never contain (mirrors tests/test_properties)."""
    return (unicodedata.category(char) in ("Cc", "Zl", "Zp", "Cf", "Cs",
                                           "Co", "Cn")
            or char in textsafe._BIDI or char in textsafe._INVISIBLE)


def _longest_mark_run(text: str) -> int:
    longest = run = 0
    for char in text:
        if unicodedata.category(char) in ("Mn", "Mc", "Me"):
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    return longest


# Hostile strings for the manufacturer/product/serial of the analysis target.
# Picked by a hash of the input, so a crash reproduces from the input alone.
_HOSTILE_STRINGS = (
    None, "", "Kingston", "DataTraveler 3.0", "AABBCCDD",
    "\x1b[2J\x1b]0;pwned\x07", "Logitech‮USB", "Á̂̃̄",
    "\ud800", "​﻿", "x" * 400, "中文\U0001f600", "\x00\x00",
    "Keyboard", "Mass Storage", "Rubber Ducky", "HID Keyboard Device",
    "Teensyduino", "USB Armory", "O.MG",
)

# One worker-private directory for the targets that need files. mkdtemp gives
# 0700, which the trust store requires of its directory (a 1777 /tmp is
# refused before the JSON is even read -- the original target never parsed).
_PRIVATE_DIR = None


def _private_dir() -> Path:
    global _PRIVATE_DIR
    if _PRIVATE_DIR is None:
        _PRIVATE_DIR = Path(tempfile.mkdtemp(prefix="probolos-fuzz-"))
        atexit.register(shutil.rmtree, _PRIVATE_DIR, ignore_errors=True)
    return _PRIVATE_DIR


def _device(blob: bytes, manufacturer, product, serial):
    """A UsbDevice the way sysfs.load_device builds one from `blob`."""
    try:
        parsed, error = descriptors.parse(blob), None
    except descriptors.DescriptorParseError as exc:
        parsed, error = None, str(exc)
    return sysfs.UsbDevice(
        syspath=Path("/sys/devices/pci0000:00/usb1/1-4"), name="1-4",
        vendor_id="0951", product_id="1666",
        manufacturer=textsafe.clean(manufacturer),
        product=textsafe.clean(product), serial=textsafe.clean(serial),
        bus=1, device_num=7, speed="480", authorized=0, device_class=0,
        descriptor_set=parsed, parse_error=error, raw_descriptors=blob,
        removable="removable", instance_id=(1, 1000))


# A ledger that already knows one device under the serial the analysis target
# reuses, so every mutated device is judged AGAINST HISTORY (drift rules),
# not only as a first sighting. Built lazily, never saved.
_LEDGER = None
_LEDGER_SERIAL = "FUZZ0001"


def _ledger():
    global _LEDGER
    if _LEDGER is None:
        from seeds import descriptor_seeds
        _LEDGER = ledger_mod.Ledger(_private_dir() / "never-written.json")
        base = _device(descriptor_seeds()[0], "Kingston", "DataTraveler",
                       _LEDGER_SERIAL)
        _LEDGER.record(base, "allowed", approved=True)
    return _LEDGER


# ---------------------------------------------------------------------------
# descriptors (stage 1-2 input: bytes the device chose)
# ---------------------------------------------------------------------------

def target_descriptors(data: bytes) -> None:
    """parse() fails only with DescriptorParseError -- the one error
    sysfs.load_device catches. (The original target also allowed
    DescriptorParsingError, which load_device does NOT catch: that would have
    hidden a real crash.) And the helpers every rule reads must hold up."""
    try:
        parsed = descriptors.parse(data)
    except descriptors.DescriptorParseError:
        return
    head = struct.unpack_from("<BBHBBBBHHH", data, 0)
    assert parsed.device.vendor_id == head[7]
    assert parsed.device.product_id == head[8]
    parsed.primary_interfaces()
    parsed.interface_classes()
    parsed.declared_power_ma()
    parsed.power_span()
    parsed.declared_interface_mismatch()


def target_descriptor_walk(data: bytes) -> None:
    """The TLV walk terminates and accounts for every byte."""
    seen = []
    try:
        for kind, desc in descriptors_safe.walk_descriptors(data):
            assert len(desc) >= 2 and desc[0] == len(desc) and desc[1] == kind
            seen.append(desc)
    except descriptors_safe.DescriptorParsingError:
        assert data.startswith(b"".join(seen))
    else:
        assert b"".join(seen) == data
    assert len(seen) <= len(data) // 2


def target_hid_report(data: bytes) -> None:
    """HID report descriptors: items fail only as designed, and are bounded."""
    count = 0
    try:
        for _item in descriptors_safe.walk_hid_items(data):
            count += 1
    except descriptors_safe.DescriptorParsingError:
        pass
    assert count <= descriptors_safe.MAX_HID_ITEMS


def target_analysis(data: bytes) -> None:
    """
    The whole verdict path for one device: parse -> every analyzer (with and
    without history) -> report and prompt text.

    analyzers.run() CONTAINS crashes as 'analyzer-failed:*' findings, so a
    plain call never raises -- a crash there is invisible to a naive fuzzer.
    Here a contained failure is re-run directly so it surfaces with its real
    traceback.
    """
    h = zlib.crc32(data)
    pick = _HOSTILE_STRINGS
    maker = pick[h % len(pick)]
    product = pick[(h >> 8) % len(pick)]
    serial = _LEDGER_SERIAL if h & 0x10000 else pick[(h >> 17) % len(pick)]
    dev = _device(data, maker, product, serial)
    ctx = analyzers.Context(device=dev,
                            ledger=_ledger() if h & 0x20000 else None)
    findings = analyzers.run(ctx)
    for f in findings:
        if f.rule_id.startswith("analyzer-failed:"):
            wanted = f.rule_id.split(":", 1)[1]
            for a in analyzers.DEFAULT_ANALYZERS:
                if a.id == wanted:
                    a.analyze(ctx)          # raises with the real traceback
            raise AssertionError(f"contained analyzer failure: {f.rule_id}")
    for text in (report.render(dev, findings),
                 report.one_liner(dev, findings),
                 daemon.Probolos._agent_title(dev),
                 daemon.Probolos._agent_body(dev, findings),
                 daemon.Probolos._agent_capabilities(dev),
                 daemon.Probolos._critical_note(findings)):
        assert isinstance(text, str)
    assert daemon.Probolos._prompt_steps(dev, findings) in (
        agentlink.STEPS_ONE, agentlink.STEPS_TWO, agentlink.STEPS_COUNTDOWN)


# ---------------------------------------------------------------------------
# storage (stage 4 input: sectors the medium chose)
# ---------------------------------------------------------------------------

def target_storage_mbr(data: bytes) -> None:
    """The MBR reader is total: at most four real, non-empty entries."""
    for part in storage.parse_mbr(data):
        assert part.index in range(4)
        assert part.type_byte != 0 and part.sectors > 0


def target_storage_gpt(data: bytes) -> None:
    """The GPT readers never return more entries than the bytes hold."""
    storage.parse_gpt_header(data)
    entries = storage.parse_gpt_entries(data)
    if entries is not None:
        room = max(0, (len(data) - 2 * storage.SECTOR) // storage.GPT_ENTRY_SIZE)
        assert len(entries) <= room


def target_storage_fs(data: bytes) -> None:
    """Filesystem / ISO9660 / UDF identification, with a size limit taken
    from the first byte so both the limited and unlimited paths run."""
    limit = None if data[:1] in (b"", b"\x00") else len(data) * data[0] // 64
    name, note = storage.identify_filesystem(data, limit)
    assert name is None or isinstance(name, str)
    assert note is None or isinstance(note, str)


_SIZE = [None]
_READS = []
_real_read_at = storage._read_at


def _fake_size(_device):
    return _SIZE[0]


def _recording_read_at(fd, offset, length):
    _READS.append(offset)
    return _real_read_at(fd, offset, length)


def target_storage_inspect(data: bytes) -> None:
    """
    The whole of stage 4: inspect() + findings + the storage analyzer + the
    rendered report, with the declared size ALSO from the input (the capacity
    lie). The medium is a real fd (memfd): no os.pread mock, the real I/O path.
    """
    if len(data) >= 9 and data[0] & 1:
        _SIZE[0] = struct.unpack_from("<Q", data, 1)[0] % (
            storage_hardening.MAX_PLAUSIBLE_SECTORS * 2)
    else:
        _SIZE[0] = None if data[:1] == b"\x02" else max(1, len(data) // 512)
    fd = os.memfd_create("fuzz-medium")
    _READS.clear()
    try:
        os.write(fd, data)
        with mock.patch.object(storage, "read_size_sectors", _fake_size), \
                mock.patch.object(storage, "_read_at", _recording_read_at):
            med = storage.inspect("/dev/sdX", open_fn=lambda _dev: fd)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass                       # inspect() closes it itself
    # A medium shorter than one sector is refused by design ("only N bytes
    # readable"); anything longer must not produce an error.
    assert med.error is None or len(data) < storage.SECTOR, med.error
    findings = rules.storage_findings(med)
    if med.size_sectors is not None:
        assert med.size_sectors <= storage_hardening.MAX_PLAUSIBLE_SECTORS
    # The reads stage 4 actually made (not safe_read_offset's own answer):
    # inside the device when its size was believed, below the cap always.
    for offset in _READS:
        assert offset <= storage_hardening.MAX_SEEK_OFFSET, hex(offset)
        if offset and med.size_sectors is not None:
            assert offset < med.size_sectors * storage.SECTOR, \
                (hex(offset), med.size_sectors)
    dev = _device(_storage_blob(), "Kingston", "DataTraveler", "S1")
    ran = analyzers.run(analyzers.Context(device=dev, extra={"medium": med}),
                        analyzers=[analyzers.StorageAnalyzer()])
    failed = [f.rule_id for f in ran if f.rule_id.startswith("analyzer-failed:")]
    if failed:
        analyzers.StorageAnalyzer().analyze(
            analyzers.Context(device=dev, extra={"medium": med}))
        raise AssertionError(f"contained analyzer failure: {failed}")
    assert isinstance(report.render_medium(med, findings), str)


def _storage_blob() -> bytes:
    from seeds import descriptor_seeds
    return descriptor_seeds()[0]


# ---------------------------------------------------------------------------
# the privilege boundary: what the (untrusted) analyzer sends the root gate
# ---------------------------------------------------------------------------

_KINDS = (protocol.REQ_AUTHORIZE, protocol.REQ_ADMIT, protocol.REQ_SET_DEFAULT,
          protocol.REQ_OPEN_INPUT, protocol.REQ_OPEN_BLOCK,
          protocol.REQ_AUTHORIZE_INTERFACE, protocol.REQ_TRUST,
          protocol.REQ_PING)


def target_protocol_request(data: bytes) -> None:
    """Any datagram decodes into a WELL-FORMED request or ValueError (the one
    error the gate's serve loop answers as 'bad request')."""
    try:
        req = protocol.Request.decode(data)
    except ValueError:
        return
    assert req.kind in _KINDS, req.kind
    assert isinstance(req.path, str) and "\x00" not in req.path
    assert req.value is None or type(req.value) is int
    if req.instance is not None:
        assert len(req.instance) == 2
        assert all(type(n) is int and n >= 0 for n in req.instance)
    for text, limit in ((req.key, protocol.MAX_KEY),
                        (req.label, protocol.MAX_LABEL)):
        if text is not None:
            assert isinstance(text, str) and "\x00" not in text
            assert len(text) <= limit
    if req.kind == protocol.REQ_TRUST:
        assert req.path and req.instance is not None
        assert req.key is not None and req.label is not None
    # A request that decoded must survive a round trip unchanged.
    assert protocol.Request.decode(req.encode()) == req


def target_protocol_response(data: bytes) -> None:
    """A gate reply decodes into a known status or ValueError."""
    try:
        resp = protocol.Response.decode(data)
    except ValueError:
        return
    assert resp.status in (protocol.OK, protocol.ERROR, protocol.DENIED)
    assert isinstance(resp.detail, str)


def target_gate_paths(data: bytes) -> None:
    """Whatever path the analyzer names, the gate answers yes/no, never
    raises, and a yes is always inside the allowed tree."""
    path = _text(data)
    usb = gate_server.GateServer._safe_usb_path(path)
    if usb is not None:
        assert str(usb).startswith(gate_server.USB_REAL_PREFIX), usb
    node = gate_server.GateServer._safe_input_path(path)
    if node is not None:
        assert str(node).startswith(gate_server.INPUT_PREFIX), node
    disk, reason = gate_server.GateServer._check_block_path(path)
    assert disk is not None or reason


# ---------------------------------------------------------------------------
# the agent socket (desktop prompts)
# ---------------------------------------------------------------------------

_LINK = None


def target_agentlink_answer(data: bytes) -> None:
    """Only an answer to THIS question is an answer."""
    global _LINK
    if _LINK is None:
        _LINK = agentlink.AgentLink(Path("/nonexistent/agent.sock"),
                                    log=lambda *_a: None)
    answer = _LINK._parse_answer(data, 7)
    assert answer in (agentlink.ANSWER_YES, agentlink.ANSWER_ALWAYS,
                      agentlink.ANSWER_NO, agentlink.ANSWER_UNAVAILABLE, None)
    if answer is not None:
        message = json.loads(data.decode())
        assert message.get("type") == agentlink.MSG_ANSWER
        assert message.get("id") == 7


def target_agent_line(data: bytes) -> None:
    """The agent survives any line and, with no dialog answering, never
    replies with an approval."""
    import threading
    replies = []
    subject = agent_mod.Agent.__new__(agent_mod.Agent)
    subject.log = lambda *_a: None
    subject.notifier = mock.Mock(**{"available.return_value": False})
    subject.dialog = mock.Mock(**{
        "confirm.return_value": None, "choose.return_value": None,
        "notice.return_value": None, "confirm_countdown.return_value": None})
    subject.countdown_dialog = subject.dialog
    subject.sock = None
    subject._notice_window = threading.Lock()
    with mock.patch.object(subject, "_reply",
                           side_effect=lambda _id, a: replies.append(a)):
        subject._handle(data)
    for answer in replies:
        assert answer not in (agentlink.ANSWER_YES, agentlink.ANSWER_ALWAYS), \
            answer


# ---------------------------------------------------------------------------
# state files
# ---------------------------------------------------------------------------

def _write_private(name: str, data: bytes) -> Path:
    path = _private_dir() / name
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


def target_ledger(data: bytes) -> None:
    """Any ledger file loads into well-typed entries or is reported."""
    store = ledger_mod.Ledger(_write_private("ledger.json", data))
    for entry in store.entries.values():
        assert isinstance(entry, ledger_mod.Entry)
        assert isinstance(entry.identity, str)
        assert type(entry.times_seen) is int
        for values in (entry.ports, entry.decisions, entry.known_hashes):
            assert all(isinstance(v, str) for v in values)


def target_trust(data: bytes) -> None:
    """Any trust store loads into well-typed entries or is reported."""
    store = trust.TrustStore(_write_private("trusted.json", data))
    # The original target ran in /tmp (mode 1777): the store refused the
    # directory and never parsed a byte. Prove we got past that check.
    assert "directory" not in (store.load_error or ""), store.load_error
    for key, entry in store.devices.items():
        assert isinstance(entry, trust.TrustedDevice)
        assert entry.key == key and entry.key and entry.descriptor_hash
        assert type(entry.times_admitted) is int and entry.times_admitted >= 0


# ---------------------------------------------------------------------------
# text and keystrokes
# ---------------------------------------------------------------------------

def target_textsafe(data: bytes) -> None:
    """First byte picks the limit and str-vs-bytes; the rest is the value."""
    limit = 1 + (data[0] if data else 0) % 200
    value = data[1:] if data[:1] and data[0] & 0x80 else _text(data[1:])
    result = textsafe.sanitize(value, limit)
    bad = [c for c in result.text if _forbidden(c)]
    assert not bad, f"dangerous {bad!r} in {result.text!r}"
    assert _longest_mark_run(result.text) <= textsafe.MAX_COMBINING_RUN
    if textsafe.NOTE_TRUNCATED in result.notes:
        assert result.text.endswith("...")
        assert len(result.text) - 3 <= limit
    else:
        assert len(result.text) <= limit
    for columns in (3, 17, 80):
        assert textsafe.display_width(textsafe.fit(result.text, columns)) \
            <= columns
        assert textsafe.display_width(textsafe.pad(result.text, columns)) \
            == columns
        assert "".join(textsafe.split_width(result.text, columns)) \
            == result.text


def target_payload(data: bytes) -> None:
    """3 bytes per event: 10-bit key code, value (press/release/repeat)."""
    max_chars = 1 + (data[0] if data else 0)
    events = []
    for i in range(1, len(data) - 2, 3):
        code = data[i] | ((data[i + 1] & 0x03) << 8)
        value = (data[i + 1] >> 2) % 3
        events.append((float(i), code, value))
    result = payload.reconstruct(events, max_chars=max_chars)
    presses = sum(1 for _t, c, v in events
                  if v == 1 and c not in payload.MODIFIERS)
    assert result.keystrokes == presses
    # The bound a hostile HID cannot reset: lines stay O(max_chars).
    assert len(result.lines) <= 2 * max_chars + 2, \
        (len(result.lines), max_chars)


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

TARGETS = {
    "descriptors":       target_descriptors,
    "descriptor_walk":   target_descriptor_walk,
    "hid_report":        target_hid_report,
    "analysis":          target_analysis,
    "storage_mbr":       target_storage_mbr,
    "storage_gpt":       target_storage_gpt,
    "storage_fs":        target_storage_fs,
    "storage_inspect":   target_storage_inspect,
    "protocol_request":  target_protocol_request,
    "protocol_response": target_protocol_response,
    "gate_paths":        target_gate_paths,
    "agentlink_answer":  target_agentlink_answer,
    "agent_line":        target_agent_line,
    "ledger":            target_ledger,
    "trust":             target_trust,
    "textsafe":          target_textsafe,
    "payload":           target_payload,
}

SEED_GROUP = {
    "descriptors": "descriptors", "descriptor_walk": "descriptors",
    "analysis": "descriptors", "hid_report": "hid",
    "storage_mbr": "disk", "storage_gpt": "disk", "storage_fs": "disk",
    "storage_inspect": "disk",
    "protocol_request": "protocol", "protocol_response": "protocol",
    "gate_paths": "paths",
    "agentlink_answer": "agent", "agent_line": "agent",
    "ledger": "ledger", "trust": "trust",
    "textsafe": "text", "payload": "payload",
}

# JSON-shaped inputs: the engine also applies structure-aware JSON mutation.
JSON_GROUPS = {"protocol", "agent", "ledger", "trust"}

# Largest input worth trying, per seed group (bigger is just slower).
MAX_SIZE = {"disk": 160 * 1024, "protocol": protocol.MAX_MESSAGE + 64,
            "agent": agentlink.MAX_MESSAGE + 64}
DEFAULT_MAX_SIZE = 8192

# Tokens worth splicing in (AFL-style dictionary), per seed group.
DICTIONARY = {
    "descriptors": [b"\x12\x01", b"\x09\x02", b"\x09\x04", b"\x07\x05",
                    b"\x09\x21", b"\x08\x0b", b"\x05\x24", b"\x05\x0f",
                    b"\x03\x01\x01", b"\x08\x06\x50", b"\xff\xff",
                    b"\x00\x02", b"\x10\x03", b"\x20\x03"],
    "hid": [b"\x05\x01", b"\x09\x06", b"\xa1\x01", b"\xc0", b"\x75\x08",
            b"\x95\xff", b"\x96\xff\xff", b"\x27\xff\xff\xff\x7f", b"\xa4",
            b"\xb4", b"\xfe\xff", b"\x81\x02", b"\x91\x02", b"\xb1\x02"],
    "disk": [b"\x55\xaa", b"EFI PART", b"\xee", b"\x0c", b"\x83", b"\x07",
             b"NTFS    ", b"EXFAT   ", b"FAT32   ", b"FAT16   ", b"CD001",
             b"BEA01", b"NSR02", b"NSR03", b"TEA01", b"\x53\xef",
             b"_BHRfS_M", b"\xff\xff\xff\xff", b"\x00\x00\x00\x80"],
    "protocol": [b'"kind"', b'"path"', b'"value"', b'"instance"', b'"key"',
                 b'"label"', b'"status"', b'"detail"', b'"authorize"',
                 b'"admit"', b'"set_default"', b'"open_input"',
                 b'"open_block"', b'"authorize_interface"', b'"trust"',
                 b'"ping"', b'"/sys/devices/', b'"/dev/input/event',
                 b'"/dev/sd', b"/../", b"\\u0000", b"1e999", b"-0",
                 b"18446744073709551616"],
    "paths": [b"/sys/devices/", b"/dev/input/", b"/dev/sda", b"/../",
              b"/./", b"//", b"\x00", b"usb1/1-4", b"authorized",
              b"/proc/self/root", b"event0", b"mouse0", b"sda1"],
    "agent": [b'"type"', b'"id"', b'"answer"', b'"decide"', b'"critical"',
              b'"cancel"', b'"notice"', b'"hello"', b'"yes"', b'"always"',
              b'"no"', b'"one"', b'"two"', b'"countdown"', b'"timeout"',
              b'"steps"', b'"allow_always"', b"\n", b"1e999", b"true"],
    "ledger": [b'"schema"', b'"entries"', b'"media"', b'"identity"',
               b'"descriptor_hash"', b'"baseline_hash"', b'"known_hashes"',
               b'"times_seen"', b'"fingerprint_scheme"', b'"ports"',
               b'"decisions"', b"null", b"[]", b"{}", b"1e999", b"-1"],
    "trust": [b'"schema"', b'"devices"', b'"key"', b'"descriptor_hash"',
              b'"identity"', b'"label"', b'"times_admitted"', b'"ports"',
              b'"note"', b"null", b"[]", b"{}", b"1e999", b"-1"],
    "text": [b"\x1b[", b"\xe2\x80\xae", b"\xe2\x81\xa6", b"\xcc\x81",
             b"\xef\xbb\xbf", b"\xed\xa0\x80", b"\xf3\xa0\x80\x81",
             b"\xe4\xb8\xad", b"\xc2\x85", b"\xe2\x80\xa8"],
    "payload": [],
}
