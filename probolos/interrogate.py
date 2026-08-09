"""
Active interrogation: asking the device questions instead of waiting for it.

THE IDEA
--------
Every other defence in this space is passive. It watches. Watching can be
defeated by patience: a payload throttled to human typing speed beats timing
analysis, and a cloned descriptor set beats identity analysis. Both are
software problems, and the attacker controls the software.

But Probolos holds the device in a state nobody else has -- enumerated,
unauthorized, no driver bound, and under no time pressure at all. In that state
it can issue arbitrary control transfers and measure the answers. And the
answers are a property of the FIRMWARE AND THE SILICON, which the attacker does
not freely control. A Raspberry Pi Pico running TinyUSB cannot cheaply pretend
to be a Cypress keyboard controller at the level of control-transfer
behaviour and latency.

This is the USB equivalent of TCP/IP stack fingerprinting: nmap does not ask a
host what operating system it runs, it observes how the stack behaves at the
edges of the specification.

STATUS: THIS IS AN EXPERIMENT, NOT A DETECTOR
---------------------------------------------
Nothing here classifies anything. It collects measurements so that the question
"are consumer USB stacks actually distinguishable from general-purpose
microcontrollers at the control-transfer layer?" can be answered with data
BEFORE any of it is wired into the daemon. If the distributions turn out to
overlap, that is worth knowing after a week of measurement rather than after
months of building on the assumption.

Run it with `interrogation_study.py`, over as many devices as you can find.

RISK, STATED UP FRONT
---------------------
Probing is not neutral. A sophisticated implant can use control transfers as a
trigger -- an unusual request is a fine wake-up signal, and this module sends
several by design. Probing a device you believe to be hostile is an active
choice, not a free lookup. Probes are ordered so that the ones resembling
ordinary enumeration come first.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

try:
    import usb.core
    import usb.util
except ImportError:  # pragma: no cover
    usb = None

# bmRequestType values
DIR_IN_STANDARD_DEVICE = 0x80
DIR_OUT_CLASS_INTERFACE = 0x21

# Standard bRequest codes
REQ_GET_STATUS = 0x00
REQ_GET_DESCRIPTOR = 0x06
REQ_GET_CONFIGURATION = 0x08
REQ_HID_SET_REPORT = 0x09

DESC_DEVICE = 0x01
DESC_STRING = 0x03

OUTCOME_OK = "ok"
OUTCOME_STALL = "stall"
OUTCOME_TIMEOUT = "timeout"
OUTCOME_ERROR = "error"


@dataclass
class ProbeResult:
    probe: str
    outcome: str
    latencies_ms: List[float] = field(default_factory=list)
    payload_len: Optional[int] = None
    detail: str = ""

    def mean_ms(self) -> Optional[float]:
        return sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else None

    def stdev_ms(self) -> Optional[float]:
        if len(self.latencies_ms) < 2:
            return None
        mean = self.mean_ms()
        var = sum((x - mean) ** 2 for x in self.latencies_ms) / len(self.latencies_ms)
        return var ** 0.5


@dataclass
class Probe:
    """One question, and how many times to ask it."""
    name: str
    description: str
    run: Callable
    repeats: int = 1
    # Probes that stay inside ordinary enumeration behaviour. Ordered first so
    # that a device is not startled before the harmless measurements are taken.
    benign: bool = True


def _timed(fn) -> (float, object):
    start = time.perf_counter()
    value = fn()
    return (time.perf_counter() - start) * 1000.0, value


def _ctrl(dev, bmRequestType, bRequest, wValue, wIndex, length_or_data,
          timeout=1000):
    return dev.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex,
                             length_or_data, timeout)


# --------------------------------------------------------------------------
# The probes
# --------------------------------------------------------------------------

def probe_device_descriptor(dev) -> object:
    """The most ordinary request there is. Baseline latency."""
    return _ctrl(dev, DIR_IN_STANDARD_DEVICE, REQ_GET_DESCRIPTOR,
                 (DESC_DEVICE << 8) | 0, 0, 18)


def probe_get_status(dev) -> object:
    """Standard, mandatory, and trivially cheap for a real controller."""
    return _ctrl(dev, DIR_IN_STANDARD_DEVICE, REQ_GET_STATUS, 0, 0, 2)


def probe_get_configuration(dev) -> object:
    return _ctrl(dev, DIR_IN_STANDARD_DEVICE, REQ_GET_CONFIGURATION, 0, 0, 1)


def probe_oversized_wlength(dev) -> object:
    """
    Ask for 255 bytes of an 18-byte descriptor.

    The specification says the device returns what it has and no more. Minimal
    stacks sometimes pad, sometimes stall, sometimes return a short packet at a
    different moment -- the divergence is the signal.
    """
    return _ctrl(dev, DIR_IN_STANDARD_DEVICE, REQ_GET_DESCRIPTOR,
                 (DESC_DEVICE << 8) | 0, 0, 255)


def probe_invalid_string_index(dev) -> object:
    """
    Request a string descriptor that almost certainly does not exist.

    Correct behaviour is a STALL. Many embedded stacks return an empty packet,
    return string 0, or hang instead.
    """
    return _ctrl(dev, DIR_IN_STANDARD_DEVICE, REQ_GET_DESCRIPTOR,
                 (DESC_STRING << 8) | 0xEE, 0x0409, 255)


def probe_unknown_request(dev) -> object:
    """
    A bRequest that does not exist. STALL is the only correct answer.

    A device that answers something here is not implementing USB, it is
    improvising -- and improvisation is characteristic of a specific library.
    """
    return _ctrl(dev, DIR_IN_STANDARD_DEVICE, 0x99, 0, 0, 8)


def probe_zero_length(dev) -> object:
    """wLength=0 on a descriptor request: legal, and handled inconsistently."""
    return _ctrl(dev, DIR_IN_STANDARD_DEVICE, REQ_GET_DESCRIPTOR,
                 (DESC_DEVICE << 8) | 0, 0, 0)


def probe_hid_set_led(dev) -> object:
    """
    Tell a keyboard to switch its Caps Lock LED on.

    A real keyboard has firmware and a physical LED, and its handling of the
    output report is characteristic. Many HID emulators declare the output
    report in their descriptors and then do nothing with it, because there is
    no LED to drive. This is the probe most likely to separate a keyboard from
    something pretending to be one -- and, for the same reason, the one most
    likely to be noticed by an implant that is watching.
    """
    return _ctrl(dev, DIR_OUT_CLASS_INTERFACE, REQ_HID_SET_REPORT,
                 0x0200, 0, [0x02])


PROBES: List[Probe] = [
    Probe("device_descriptor", "GET_DESCRIPTOR(device) baseline latency",
          probe_device_descriptor, repeats=20),
    Probe("get_status", "GET_STATUS(device)", probe_get_status, repeats=10),
    Probe("get_configuration", "GET_CONFIGURATION", probe_get_configuration,
          repeats=10),
    Probe("oversized_wlength", "GET_DESCRIPTOR with wLength=255",
          probe_oversized_wlength, repeats=5),
    Probe("zero_length", "GET_DESCRIPTOR with wLength=0",
          probe_zero_length, repeats=5),
    Probe("invalid_string_index", "GET_DESCRIPTOR(string 0xEE)",
          probe_invalid_string_index, repeats=5, benign=False),
    Probe("unknown_request", "bRequest=0x99 (undefined)",
          probe_unknown_request, repeats=5, benign=False),
    Probe("hid_set_led", "HID SET_REPORT output (Caps Lock LED)",
          probe_hid_set_led, repeats=5, benign=False),
]


def interrogate(dev, probes: Optional[List[Probe]] = None,
                include_intrusive: bool = True) -> Dict[str, ProbeResult]:
    """
    Run the probe battery against one pyusb device handle.

    Benign probes always run first: if an intrusive probe wedges the device,
    the ordinary measurements have already been collected.
    """
    chosen = probes if probes is not None else PROBES
    ordered = [p for p in chosen if p.benign]
    if include_intrusive:
        ordered += [p for p in chosen if not p.benign]

    results: Dict[str, ProbeResult] = {}
    for probe in ordered:
        result = ProbeResult(probe=probe.name, outcome=OUTCOME_OK)
        for _ in range(probe.repeats):
            try:
                elapsed, value = _timed(lambda: probe.run(dev))
                result.latencies_ms.append(elapsed)
                try:
                    result.payload_len = len(value)
                except TypeError:
                    result.payload_len = None
            except Exception as exc:  # pyusb raises USBError subclasses
                result.outcome = _classify_error(exc)
                result.detail = f"{type(exc).__name__}: {exc}"
                break
        results[probe.name] = result
    return results


def _classify_error(exc) -> str:
    text = str(exc).lower()
    if "pipe" in text or "stall" in text:
        return OUTCOME_STALL
    if "time" in text:
        return OUTCOME_TIMEOUT
    return OUTCOME_ERROR


def summarize(results: Dict[str, ProbeResult]) -> Dict[str, object]:
    """
    Flatten a probe battery into one row for the study CSV.

    Kept as a pure function so the analysis half of this module is testable
    without any USB hardware at all.
    """
    row: Dict[str, object] = {}
    for name, result in results.items():
        row[f"{name}__outcome"] = result.outcome
        mean = result.mean_ms()
        stdev = result.stdev_ms()
        row[f"{name}__mean_ms"] = round(mean, 4) if mean is not None else ""
        row[f"{name}__stdev_ms"] = round(stdev, 4) if stdev is not None else ""
        row[f"{name}__len"] = result.payload_len if result.payload_len is not None else ""
    return row


def fieldnames(probes: Optional[List[Probe]] = None) -> List[str]:
    names = []
    for probe in (probes if probes is not None else PROBES):
        names += [f"{probe.name}__outcome", f"{probe.name}__mean_ms",
                  f"{probe.name}__stdev_ms", f"{probe.name}__len"]
    return names
