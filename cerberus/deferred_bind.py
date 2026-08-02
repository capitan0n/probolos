"""
deferred_bind.py — Closing the race window via interface-level authorization.

THE PROBLEM IT SOLVES
---------------------
Today the flow is: authorized=1  ->  the kernel binds usbhid IMMEDIATELY  ->
an evdev node is created  ->  we grab. Between the driver binding and our grab,
41-85 ms elapse (measured on real hardware) during which the device's
keystrokes reach the session. That is the race window of quarantine.py.

The Linux kernel (>= 4.4) exposes authorization PER INTERFACE, not only per
device:

    /sys/bus/usb/devices/<dev>/authorized              <- the whole device
    /sys/bus/usb/devices/<dev>:<cfg>.<intf>/authorized <- one interface

If an interface is authorized=0, the kernel CONFIGURES it but does NOT bind a
driver to it. No driver -> no usbhid -> no evdev node -> the reports have no
path into the input subsystem.

THE NEW STRATEGY
----------------
    1. Set every interface authorized=0  (while the device is still off)
    2. Set the device authorized=1        (configured, NO driver binds)
    3. Start the monitor
    4. Set the interfaces authorized=1 ONE BY ONE; now the driver binds, the
       node appears, we grab it
The window does not shrink — it ceases to exist, because the driver never
binds before we are ready to grab.

WHY INTERFACE-LEVEL AND NOT drivers_autoprobe=0
-----------------------------------------------
The global switch /sys/bus/usb/drivers_autoprobe is system-wide state. If
Cerberus dies with the switch at 0, NO new device on the WHOLE system gets a
driver — the same lockout gate.py fights to prevent, in worse form. Interface
authorization is per-device: what we touch affects only that device, and if
something goes wrong the damage is limited to it.

FAIL-SAFE
---------
Every interface we set to 0 is recorded. The context manager restores them all
to 1 on exit — on normal exit AND on exception — so a device that was approved
is not left with dead interfaces. If the device is unplugged in between, the
restore silently ignores the lost paths.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, List, Optional

from . import sysfs

# Interface directories: <bus>-<port>[.<port>...]:<config>.<interface>
# e.g. 3-1:1.0, 3-10:1.1. The config is always present, as is the interface.
_INTERFACE_RE = re.compile(r":\d+\.\d+$")


def interface_dirs(usb_syspath: Path) -> List[Path]:
    """The interface directories belonging to THIS device.

    TWO PATH FORMS — both must work (bug #1/#5 again):

      bus-view (symlink):   /sys/bus/usb/devices/3-1
          here interfaces are SIBLINGS: /sys/bus/usb/devices/3-1:1.0
          (the directory is flat, everything side by side)

      resolved (pyudev):    /sys/devices/pci.../usb3/3-1
          here interfaces are CHILDREN: .../usb3/3-1/3-1:1.0
          (the real device tree, hierarchical)

    The daemon passes the resolved form (device.sys_path from pyudev), so if we
    searched only siblings we would find 0 interfaces and silently fall back —
    which is exactly what was happening. We search both locations.

    An interface of '3-1' is always named '3-1:<cfg>.<intf>', wherever it sits.
    The ':' after the name is what distinguishes '3-1:1.0' from '3-10:1.0' —
    without it, the prefix '3-1' would wrongly match '3-10' too.
    """
    name = usb_syspath.name
    prefix = name + ":"
    result: List[Path] = []
    seen: set = set()

    # Search BOTH inside the device dir itself (children, resolved form)
    # AND in its parent (siblings, bus-view form).
    for base in (usb_syspath, usb_syspath.parent):
        try:
            entries = sorted(base.iterdir())
        except OSError:
            # The device was unplugged or the path does not exist — skip.
            continue
        for entry in entries:
            if entry.name in seen:
                continue
            if entry.name.startswith(prefix) and _INTERFACE_RE.search(entry.name):
                if (entry / "authorized").exists():
                    result.append(entry)
                    seen.add(entry.name)
    return result


def supported(usb_syspath: Path) -> bool:
    """True if this device exposes per-interface authorized attributes.

    If it returns False, the caller must fall back to the old behaviour
    (whole-device authorize + grab-race). The new strategy is not available on
    every kernel/device, and we break nothing when it is missing.
    """
    return len(interface_dirs(usb_syspath)) > 0


class DeferredBind:
    """Holds a device's interfaces unbound, and releases them under control.

    Use as a context manager INSIDE the quarantine authorize_fn:

        with DeferredBind(dev.syspath) as db:
            db.authorize_device()      # device on, no driver
            ... (the caller starts the monitor) ...
            db.release_interfaces()    # now drivers bind, nodes appear

    On exit, any interface left at 0 is restored to 1, so an approved device is
    not left half-dead if something is thrown in between.
    """

    def __init__(self, usb_syspath: Path, log: Callable[[str], None] = print,
                 dry_run: bool = False):
        self.syspath = usb_syspath
        self.log = log
        self.dry_run = dry_run
        self.interfaces = interface_dirs(usb_syspath)
        self._deauthorized: List[Path] = []
        self._device_authorized = False

    def __enter__(self) -> "DeferredBind":
        # STEP 1: close every interface BEFORE powering on the device. That way
        # when the device becomes authorized=1, the kernel has nothing to bind
        # a driver to.
        for intf in self.interfaces:
            if not self.dry_run:
                _write_interface_authorized(intf, 0)
            self._deauthorized.append(intf)
        self.log(f"  - {self.syspath.name}: {len(self._deauthorized)} interface(s) "
                 f"held unbound before power-on")
        return self

    def authorize_device(self) -> None:
        """STEP 2: power on the device. It is configured; no driver binds."""
        if not self.dry_run:
            sysfs.set_authorized(self.syspath, 1)
        self._device_authorized = True

    def release_interfaces(self) -> None:
        """STEP 4: allow binding, one interface at a time.

        As each interface becomes 1, the kernel binds its driver and (for HID)
        the evdev node appears — which the quarantine monitor is already
        waiting for. Because we remove them from _deauthorized as they are
        released, __exit__ will not try to set them again.
        """
        for intf in list(self._deauthorized):
            if not self.dry_run:
                _write_interface_authorized(intf, 1)
            self._deauthorized.remove(intf)

    def __exit__(self, exc_type, exc, tb) -> bool:
        # Fail-safe: any interface left at 0 (e.g. an error before release, or
        # interfaces we did not get to) is restored to 1. An approved device
        # must not be left with dead interfaces.
        #
        # NOTE on the logic: if the device was NOT approved in the end (the user
        # said no), its interfaces are irrelevant anyway — the whole device will
        # be set authorized=0 by the daemon and the interfaces cease to exist.
        # The restore-to-1 here is safe either way: on a deauthorized device it
        # does no harm.
        for intf in self._deauthorized:
            try:
                if not self.dry_run:
                    _write_interface_authorized(intf, 1)
            except OSError:
                pass  # device unplugged; the path is gone, no matter
        self._deauthorized.clear()
        return False  # never swallow exceptions


def _write_interface_authorized(intf_dir: Path, value: int) -> None:
    """Writes an interface's authorized attribute, via the sysfs backend.

    Goes through the same backend as the other privileged writes, so that under
    privilege separation the write happens in the root gate and not here.
    """
    sysfs.set_interface_authorized(intf_dir, value)
