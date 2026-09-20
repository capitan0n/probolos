"""
Stage 3: behavioural quarantine for input devices.

THE CHICKEN-AND-EGG PROBLEM
---------------------------
Stages 1-2 judge what a device CLAIMS. A competent BadUSB claims to be an
ordinary keyboard, with a plausible vendor and a single HID interface, and
passes every one of those checks. The only thing left that can distinguish it
is what it DOES.

But a keyboard cannot do anything while unauthorized, and once authorized its
keystrokes go straight to whatever window has focus. Observing behaviour seems
to require accepting the risk we are trying to avoid.

The way out is EVIOCGRAB. Grabbing an evdev node gives one process exclusive
access to it: events reach the grabbing process and nowhere else -- not the
terminal, not X, not Wayland, not the focused window. So the sequence is:

    authorized=1  →  grab immediately  →  observe in isolation  →  decide
                                                                    │
                                            release grab ───────────┤
                                            or authorized=0 ────────┘

The device is alive but talking into a closed room.

THE RACE, STATED HONESTLY
-------------------------
Between writing authorized=1 and completing the grab there is a window in which
keystrokes CAN reach the session. The kernel must probe the device, bind
usbhid, and create /dev/input/eventN before anything can be grabbed at all.

We shrink that window as far as the design allows -- the udev monitor for the
input subsystem is started BEFORE authorization, so we are already blocked in
poll() when the node appears -- and we MEASURE it, reporting the actual elapsed
milliseconds rather than claiming there is no gap. Most off-the-shelf payloads
wait several hundred milliseconds before typing, because firing earlier loses
keystrokes to an incomplete enumeration; against those, the grab wins. Against
a payload tuned to fire at the earliest possible instant, it may not.

That limitation is real and is printed in the report. A security tool that
hides its race conditions is lying.

SELF-HEALING
------------
A grab is held by an open file descriptor. If this process dies for any reason,
the kernel closes the fd and the grab is released automatically. There is no
way for Probolos to leave a keyboard permanently captured.
"""

from __future__ import annotations

import fcntl
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from . import sysfs
from contextlib import contextmanager

@contextmanager
def _null_context():
    yield


try:
    import pyudev
except ImportError:  # pragma: no cover
    pyudev = None

# --------------------------------------------------------------------------
# evdev, done directly.
#
# We used to depend on python-evdev, but it opens the device node itself from a
# path -- which is impossible for the unprivileged analyzer under privilege
# separation, where the node arrives as an already-open file descriptor passed
# from the root gate. Talking to the kernel ourselves removes the dependency
# AND leaves one code path that works in both modes, instead of two that drift.
#
# The interface is small: one ioctl to take exclusive control, and a fixed
# 24-byte struct to read.
# --------------------------------------------------------------------------

# EVIOCGRAB = _IOW('E', 0x90, int)
EVIOCGRAB = (1 << 30) | (ord('E') << 8) | 0x90 | (4 << 16)

# struct input_event { struct timeval time; __u16 type; __u16 code; __s32 value; }
# On 64-bit Linux: two longs for the timeval, then 2+2+4.
INPUT_EVENT_FORMAT = "llHHi"
INPUT_EVENT_SIZE = struct.calcsize(INPUT_EVENT_FORMAT)

EV_KEY = 0x01
EV_REL = 0x02
EV_ABS = 0x03
MAX_EVENTS = 65536


def _grab(fd: int) -> None:
    """Take exclusive control of an input device. Events then reach only us."""
    fcntl.ioctl(fd, EVIOCGRAB, 1)


def _ungrab(fd: int) -> None:
    try:
        fcntl.ioctl(fd, EVIOCGRAB, 0)
    except OSError:
        pass


# Mouse buttons are EV_KEY events too. BTN_* occupies 0x100-0x151; below and
# above that range the codes are KEY_*. Without this split, every click on an
# ordinary mouse would be counted as a keystroke and the device would be
# accused of typing -- a false positive on the most common device there is.
BTN_RANGE_START = 0x100
BTN_RANGE_END = 0x151


def is_keyboard_key(code: int) -> bool:
    """True for keys that enter text or commands, false for buttons."""
    return code > 0 and not (BTN_RANGE_START <= code <= BTN_RANGE_END)


@dataclass(frozen=True)
class KeyPress:
    """
    One key-down event.

    `code` is None unless payload capture was explicitly requested. Timing
    analysis needs only the moment a key arrived, not which key it was, so the
    default configuration cannot reconstruct anything a person typed even in
    memory. Recording WHAT was pressed is a separate, opted-into act.
    """
    timestamp: float
    code: Optional[int] = None


@dataclass
class Observation:
    """What happened while the device was held in the closed room."""
    duration: float = 0.0
    race_window: float = 0.0        # seconds between authorize and first grab
    exposure_window: float = 0.0    # seconds a live node existed BEFORE we grabbed it
    first_node_at: float = 0.0      # internal: when the first input node appeared
    nodes: List[str] = field(default_factory=list)
    grabbed: List[str] = field(default_factory=list)
    grab_failures: List[str] = field(default_factory=list)
    capture: bool = False           # was payload capture requested?
    key_presses: List[KeyPress] = field(default_factory=list)
    raw_events: List[tuple] = field(default_factory=list)  # only when capture
    button_presses: int = 0         # mouse clicks: normal, never suspicious
    motion_events: int = 0
    error: Optional[str] = None
    limit_reached: bool = False
    # Set when the device could NOT be put back to authorized=0 after the
    # observation. This is the one failure mode where the report must not read
    # as a normal quarantine: the device is still live and unwatched.
    reblock_error: Optional[str] = None

    @property
    def observed(self) -> bool:
        """True if we actually isolated at least one node."""
        return bool(self.grabbed)

    def intervals(self) -> List[float]:
        """Gaps between consecutive key presses, in seconds."""
        stamps = [k.timestamp for k in self.key_presses]
        return [b - a for a, b in zip(stamps, stamps[1:])]

    def time_to_first_key(self) -> Optional[float]:
        """Seconds from the start of observation to the first keystroke."""
        if not self.key_presses:
            return None
        return self.key_presses[0].timestamp


def available() -> bool:
    """Only pyudev is required now; the evdev side is handled directly."""
    return pyudev is not None


def find_input_nodes(usb_syspath: Path, context=None) -> List[str]:
    """
    Find the /dev/input/event* nodes belonging to one USB device.

    Walks the udev tree rather than guessing by name: a device's event nodes
    are descendants of its USB sysfs path. This matters enormously -- grabbing
    the wrong node would capture the user's real keyboard and lock them out of
    their own machine.
    """
    if pyudev is None:
        return []
    ctx = context or pyudev.Context()
    # Both sides must be compared in the SAME form. usb_syspath usually arrives
    # as the bus view (/sys/bus/usb/devices/3-1, a symlink), while udev reports
    # sys_path already resolved (/sys/devices/pci.../3-1). Comparing them
    # directly never matches, so quarantine silently found no input nodes and
    # reported "nothing to observe" for every real device -- a bug that hid
    # itself by looking like an absence of evidence.
    target = os.path.realpath(str(usb_syspath))
    nodes = []
    for dev in ctx.list_devices(subsystem="input"):
        node = dev.device_node
        if not node or not node.startswith("/dev/input/event"):
            continue
        if os.path.realpath(str(dev.sys_path)).startswith(target + "/"):
            nodes.append(node)
    return sorted(nodes)


def quarantine(usb_syspath: Path, authorize_fn, duration: float = 3.0,
               settle_timeout: float = 2.0, capture: bool = False,
               release_fn=None, bind_context=None, deauthorize_fn=None) -> Observation:
    """Observe temporarily, then block BEFORE releasing any input grab.

    Monitoring a udev event is asynchronous: neither this function nor deferred
    binding eliminates the interval between driver binding and EVIOCGRAB.
    """
    obs = Observation(duration=duration, capture=capture)
    if not available():
        obs.error = "python-pyudev is required"
        return obs
    ctx = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(ctx)
    monitor.filter_by(subsystem="input")
    monitor.start()
    devices = []
    seen = set()
    deauthorize = deauthorize_fn or (lambda: sysfs.set_authorized(usb_syspath, 0))
    cm = bind_context if bind_context is not None else _null_context()
    authorized_at = time.monotonic()
    wall_start = time.time()

    def discover():
        # Keep discovering throughout collection. A second HID node can appear
        # after the first has already been grabbed.
        for node in find_input_nodes(usb_syspath, ctx):
            if node in seen:
                continue
            seen.add(node)
            obs.nodes.append(node)
            if not obs.first_node_at:
                obs.first_node_at = time.monotonic()
            fd = None
            try:
                fd = sysfs.open_input_node(node)
                _grab(fd)
                devices.append(fd)
                obs.grabbed.append(node)
                if not obs.race_window:
                    now = time.monotonic()
                    obs.race_window = now - authorized_at
                    obs.exposure_window = now - obs.first_node_at
            except OSError as exc:
                obs.grab_failures.append(f"{node}: {exc}")
                obs.error = "input isolation failed; observation stopped"
                if fd is not None:
                    os.close(fd)
                return False
        return True

    try:
        with cm:
            authorize_fn()
            if release_fn is not None:
                release_fn()
        deadline = time.monotonic() + settle_timeout
        while time.monotonic() < deadline:
            if not discover():
                return obs
            if devices:
                break
            monitor.poll(timeout=min(0.05, max(0, deadline - time.monotonic())))
        if not devices:
            obs.error = "no input nodes appeared; nothing to observe"
            return obs
        _collect(devices, obs, duration, discover=discover, wall_start=wall_start)
        return obs
    finally:
        # Covers failed authorization, driver probing, discovery, collection,
        # signals and ordinary completion. Never wait for human input here.
        #
        # The re-block is REPORTED, never raised. Letting the OSError out was a
        # fail-open: `quarantine()` is called from `Daemon._on_add`, which the
        # udev poll loop invokes with no handler, so the single most ordinary
        # event on a machine -- someone pulling the device out during the three
        # observation seconds -- produced ENODEV here and killed the daemon.
        # From that moment nothing is gated at all, which is precisely the
        # state deny-by-default exists to prevent. The failure still has to be
        # loud, because a device left authorized is the dangerous case, so it
        # is recorded on the Observation and the rules turn it into a finding.
        try:
            deauthorize()
        except OSError as exc:
            obs.reblock_error = str(exc)
        finally:
            for fd in devices:
                _ungrab(fd)
                try:
                    os.close(fd)
                except OSError:
                    pass


def _collect(fds, obs: Observation, duration: float, discover=None,
             wall_start=None) -> None:
    """Drain grabbed nodes while discovering late nodes under the same deadline."""
    import select
    start = time.monotonic()
    wall_start = time.time() if wall_start is None else wall_start
    end = start + duration
    gone = set()
    while time.monotonic() < end:
        if discover is not None and not discover():
            return
        live = set(fds) - gone
        if not live:
            return
        ready, _, _ = select.select(list(live), [], [],
                                     min(0.05, max(0, end - time.monotonic())))
        for fd in ready:
            try:
                data = os.read(fd, INPUT_EVENT_SIZE * 64)
            except BlockingIOError:
                continue
            except OSError:
                gone.add(fd)
                continue
            if not data:
                gone.add(fd)
                continue
            for offset in range(0, len(data) - INPUT_EVENT_SIZE + 1,
                                INPUT_EVENT_SIZE):
                sec, usec, etype, code, value = struct.unpack(
                    INPUT_EVENT_FORMAT, data[offset:offset + INPUT_EVENT_SIZE])
                # evdev defaults to CLOCK_REALTIME. Use the kernel event time,
                # not the time Python drains a batch of queued events.
                event_offset = max(0.0, sec + usec / 1_000_000 - wall_start)
                _record_event(etype, code, value, obs, start,
                              event_offset=event_offset)
                if obs.limit_reached:
                    return


def _record_event(etype: int, code: int, value: int,
                  obs: Observation, start: float, event_offset=None) -> None:
    if len(obs.key_presses) >= MAX_EVENTS or len(obs.raw_events) >= MAX_EVENTS:
        obs.limit_reached = True
        obs.error = "event limit reached; observation stopped"
        return
    offset = (time.monotonic() - start if event_offset is None else event_offset)
    if etype == EV_KEY and value == 1:
        # value 1 == key down. Releases and auto-repeats are excluded so the
        # timing statistics measure intent, not key-hold duration.
        if is_keyboard_key(code):
            obs.key_presses.append(KeyPress(
                timestamp=offset,
                code=code if obs.capture else None))
        else:
            obs.button_presses += 1
    elif etype in (EV_REL, EV_ABS):
        obs.motion_events += 1

    # Modifier state needs key-up as well as key-down, so payload capture keeps
    # the full event stream. Nothing here runs unless capture was requested.
    if obs.capture and etype == EV_KEY:
        obs.raw_events.append((offset, code, value))
