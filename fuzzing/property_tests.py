"""
Property tests NOT already in tests/test_properties.py.

The repo's tests/test_properties.py already covers parser totality
(descriptors, HID items, MBR/GPT, filesystems, inspect), textsafe, the gate
protocol, the agent socket and state files -- and runs in CI. What it does not
have is the POLICY invariants below: what the rules must conclude, not only
that they don't crash. These are candidates to move into
tests/test_properties.py (same Hypothesis profiles), so CI holds them too.

    python -m pytest fuzzing/property_tests.py -q
    HYPOTHESIS_PROFILE=deep python -m pytest fuzzing/property_tests.py -q

Devices are real sysfs.UsbDevice objects built from real descriptor bytes
(the original file used a hand-written fake, which can pass while the real
object would not).
"""
import os
import struct
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]

from probolos import payload, rules, storage, storage_hardening  # noqa: E402
from targets import _device                                       # noqa: E402
from tests._support import descriptor_blob                        # noqa: E402

settings.register_profile("dev", deadline=None, max_examples=300)
settings.register_profile("deep", deadline=None, max_examples=10000)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))


def _judge(*interfaces):
    dev = _device(descriptor_blob(*interfaces), "Acme", "Widget", "S1")
    findings = rules.evaluate(dev)
    return rules.worst(findings), [f.rule_id for f in findings]


STORAGE = (0x08, 0x06, 0x50)
any_hid = st.tuples(st.just(0x03), st.integers(0, 255), st.integers(0, 255))


# ---------------------------------------------------------------------------
# Rules: the conclusions, not just "no crash"
# ---------------------------------------------------------------------------

@given(hid=any_hid, hid_first=st.booleans())
def test_storage_plus_any_hid_is_at_least_a_warning(hid, hid_first):
    """Mass storage + ANY HID interface (any subclass/protocol, either
    order) is the BadUSB shape: never below WARNING. Before the fix,
    storage + HID(0,0) came out as NOTICE."""
    ifaces = (hid, STORAGE) if hid_first else (STORAGE, hid)
    worst, ids = _judge(*ifaces)
    assert worst >= rules.Severity.WARNING, (hid, worst.label, ids)


@given(subclass=st.integers(0, 255), protocol=st.integers(0, 255))
def test_a_lone_hid_interface_never_alarms(subclass, protocol):
    """One HID interface on its own is a mouse/keyboard/gamepad: never
    WARNING or CRITICAL, or users learn to click through alarms."""
    worst, ids = _judge((0x03, subclass, protocol))
    assert worst < rules.Severity.WARNING, (subclass, protocol, worst.label,
                                            ids)


# ---------------------------------------------------------------------------
# Stage 4: a lying medium
# ---------------------------------------------------------------------------

def _inspect(buf: bytes, size):
    fd = os.memfd_create("prop-medium")
    os.write(fd, buf)
    real = storage.read_size_sectors
    storage.read_size_sectors = lambda _d: size
    try:
        return storage.inspect("/dev/sdX", open_fn=lambda _d: fd)
    finally:
        storage.read_size_sectors = real
        try:
            os.close(fd)
        except OSError:
            pass


@st.composite
def past_the_end(draw):
    """A partition that provably ends past the device -- built directly
    rather than filtered with assume() (the original tripped Hypothesis'
    filter_too_much health check: 5 valid inputs out of 55)."""
    size = draw(st.integers(1, min(storage_hardening.MAX_PLAUSIBLE_SECTORS,
                                   0xFFFFFFFF)))
    start = draw(st.integers(0, size - 1))
    sectors = draw(st.integers(size - start + 1,
                               max(size - start + 1, 0xFFFFFFFF)))
    return start, min(sectors, 0xFFFFFFFF), size


@given(past_the_end())
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_a_partition_past_the_end_is_always_flagged(case):
    start, sectors, size = case
    if start + sectors <= size:          # clamped by the 32-bit field
        return
    b = bytearray(512)
    struct.pack_into("<BBBBBBBBII", b, 446, 0, 0, 0, 0, 0x0C, 0, 0, 0,
                     start, sectors)
    struct.pack_into("<H", b, 510, 0xAA55)
    med = _inspect(bytes(b), size)
    titles = {f.title for f in rules.storage_findings(med)}
    assert (med.suspicious
            or "A partition claims space past the end of the device"
            in titles), (start, sectors, size, titles)


@given(st.binary(max_size=8 * 512),
       st.one_of(st.none(),
                 st.integers(0, storage_hardening.MAX_PLAUSIBLE_SECTORS * 2)))
def test_no_read_is_ever_planned_past_the_seek_cap(data, size):
    med = _inspect(data, size)
    rules.storage_findings(med)
    if med.size_sectors is not None:
        assert med.size_sectors <= storage_hardening.MAX_PLAUSIBLE_SECTORS
    for p in med.partitions:
        off = storage_hardening.safe_read_offset(p.start_lba, med.size_sectors)
        assert off is None or off <= storage_hardening.MAX_SEEK_OFFSET


# ---------------------------------------------------------------------------
# Payload: the bound must not be resettable (ENTER used to reset it)
# ---------------------------------------------------------------------------

@given(bursts=st.integers(1, 500), max_chars=st.integers(1, 200))
def test_payload_bound_survives_enter(bursts, max_chars):
    events = []
    for _ in range(bursts):
        events += [(0.0, 30, 1), (0.0, 30, 0), (0.0, 28, 1), (0.0, 28, 0)]
    result = payload.reconstruct(events, max_chars=max_chars)
    assert result.keystrokes == bursts * 2       # forensic count is complete
    if bursts * 2 > max_chars:
        assert result.truncated
    assert len(result.lines) <= max_chars + 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
