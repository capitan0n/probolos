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
way for Cerberus to leave a keyboard permanently captured.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import evdev
except ImportError:  # pragma: no cover
    evdev = None

try:
    import pyudev
except ImportError:  # pragma: no cover
    pyudev = None


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
    nodes: List[str] = field(default_factory=list)
    grabbed: List[str] = field(default_factory=list)
    grab_failures: List[str] = field(default_factory=list)
    capture: bool = False           # was payload capture requested?
    key_presses: List[KeyPress] = field(default_factory=list)
    raw_events: List[tuple] = field(default_factory=list)  # only when capture
    button_presses: int = 0         # mouse clicks: normal, never suspicious
    motion_events: int = 0
    error: Optional[str] = None

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
    return evdev is not None and pyudev is not None


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
    target = str(usb_syspath)
    nodes = []
    for dev in ctx.list_devices(subsystem="input"):
        node = dev.device_node
        if not node or not node.startswith("/dev/input/event"):
            continue
        # ancestry check: is this input node underneath our USB device?
        if str(dev.sys_path).startswith(target + "/"):
            nodes.append(node)
    return sorted(nodes)


def quarantine(usb_syspath: Path, authorize_fn, duration: float = 3.0,
               settle_timeout: float = 2.0,
               capture: bool = False) -> Observation:
    """
    Authorize the device, immediately isolate its input nodes, and watch.

    `authorize_fn` is injected rather than called directly so that the caller
    keeps ownership of the authorization decision, and so this function can be
    exercised in tests without touching /sys.
    """
    obs = Observation(duration=duration, capture=capture)

    if not available():
        obs.error = ("python-evdev and python-pyudev are required "
                     "(Manjaro: sudo pacman -S python-evdev python-pyudev)")
        return obs

    ctx = pyudev.Context()

    # Start listening BEFORE authorizing. Every millisecond spent setting up
    # the monitor after authorization would be a millisecond of exposure.
    monitor = pyudev.Monitor.from_netlink(ctx)
    monitor.filter_by(subsystem="input")
    monitor.start()

    authorized_at = time.monotonic()
    authorize_fn()

    devices = []
    deadline = authorized_at + settle_timeout
    seen: set = set()

    # Grab each node the instant it appears, rather than waiting for the whole
    # device to settle and then grabbing them all.
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        udev_dev = monitor.poll(timeout=max(0.01, min(0.2, remaining)))
        if udev_dev is not None and udev_dev.action != "add":
            continue

        for node in find_input_nodes(usb_syspath, ctx):
            if node in seen:
                continue
            seen.add(node)
            obs.nodes.append(node)
            try:
                dev = evdev.InputDevice(node)
                dev.grab()
                devices.append(dev)
                obs.grabbed.append(node)
                if obs.race_window == 0.0:
                    obs.race_window = time.monotonic() - authorized_at
            except (OSError, PermissionError) as exc:
                obs.grab_failures.append(f"{node}: {exc}")

        # Once we hold something, stop waiting for stragglers: extra dwell here
        # is pure exposure. Late-appearing nodes are noted as ungrabbed below.
        if devices and udev_dev is None:
            break

    if not devices:
        obs.error = obs.error or "no input nodes appeared; nothing to observe"
        return obs

    try:
        _collect(devices, obs, duration)
    finally:
        # Releasing is best-effort: closing the fd releases the grab anyway.
        for dev in devices:
            try:
                dev.ungrab()
            except OSError:
                pass
            try:
                dev.close()
            except OSError:
                pass

    return obs


def _collect(devices, obs: Observation, duration: float) -> None:
    """Read events from the grabbed nodes for `duration` seconds."""
    import select

    fd_map = {dev.fd: dev for dev in devices}
    start = time.monotonic()
    end = start + duration

    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select(list(fd_map), [], [], remaining)
        for fd in ready:
            dev = fd_map[fd]
            try:
                for event in dev.read():
                    _record_event(event, obs, start)
            except BlockingIOError:
                continue
            except OSError:
                # Device yanked out mid-observation. Not an error: unplugging
                # is a perfectly normal thing for a person to do.
                fd_map.pop(fd, None)
        if not fd_map:
            break


def _record_event(event, obs: Observation, start: float) -> None:
    offset = time.monotonic() - start
    if event.type == evdev.ecodes.EV_KEY and event.value == 1:
        # value 1 == key down. Releases and auto-repeats are excluded so the
        # timing statistics measure intent, not key-hold duration.
        if is_keyboard_key(event.code):
            obs.key_presses.append(KeyPress(
                timestamp=offset,
                code=event.code if obs.capture else None))
        else:
            obs.button_presses += 1

    # Modifier state needs key-up as well as key-down, so payload capture keeps
    # the full event stream. Nothing here runs unless capture was requested.
    if obs.capture and event.type == evdev.ecodes.EV_KEY:
        obs.raw_events.append((offset, event.code, event.value))
    elif event.type in (evdev.ecodes.EV_REL, evdev.ecodes.EV_ABS):
        obs.motion_events += 1
