"""
deferred_bind.py — Authorizing a device without letting a driver bind to it.

THE PROBLEM
-----------
The default flow is: authorized=1 -> the kernel binds usbhid IMMEDIATELY -> an
evdev node appears -> we grab it. Between the bind and the grab, 41-85 ms
elapse (measured on real hardware) during which the device's keystrokes reach
the session. That is the race window quarantine.py lives with.

WHY THE PREVIOUS VERSION OF THIS FILE DID NOTHING
-------------------------------------------------
It tried to close the window by setting each interface's `authorized` attribute
to 0 *before* powering the device on, and checked whether that was possible by
counting interface directories:

    def supported(usb_syspath):        # old
        return len(interface_dirs(usb_syspath)) > 0

The interface directories do not exist at that point. The kernel creates them
inside usb_set_configuration(), which runs only AFTER the device is authorized
-- a fact documented at the top of descriptors.py, which is the whole reason
that file has to parse the raw descriptor blob in the first place.

So supported() counted an empty directory listing, returned False every single
time, and the daemon silently took the racy fallback path. The code was
correct about the mechanism and wrong about when it could run, and because the
failure was a silent fallback rather than an error, the tool reported a closed
window it had never closed. There was no test on this module to catch it.

THE MECHANISM THAT ACTUALLY WORKS
---------------------------------
The ordering problem is real and cannot be solved with interface authorization
alone. Something must stop the driver binding at the instant the interfaces are
created, and the only kernel control that acts at that instant is the bus-wide
autoprobe switch:

    1. save /sys/bus/usb/drivers_autoprobe, write 0
    2. write authorized=1 to the device
         -> the kernel configures it and CREATES the interface directories,
            but bus_probe_device() sees autoprobe=0 and binds nothing
    3. the interface directories now exist. Write 0 to each one, which makes
       the refusal to bind a property of THIS DEVICE rather than of the bus
    4. restore drivers_autoprobe                <-- global window ends here
    5. the caller starts its monitor
    6. write 1 to each interface, then write its name to
       /sys/bus/usb/drivers_probe. Only now does usbhid attach and the evdev
       node appear -- with the monitor already waiting for it.

The window does not shrink; it ceases to exist, because no driver binds until
step 6, and step 6 happens after the monitor is listening.

THE RISK, STATED PLAINLY
------------------------
Steps 1-4 leave the entire USB bus unable to auto-bind drivers. If the process
dies in that span, no device on the machine binds a driver until someone writes
1 back by hand -- which is the lockout gate.py was written to prevent, in a
worse form.

Three things bound it:

  * the span covers exactly two sysfs writes and one directory listing, with no
    I/O to the device and no waiting on a human
  * an atexit restore is registered BEFORE the first write to 0, so the
    interpreter shutting down for any reason puts it back
  * the value is remembered in a module-level record that emergency_restore()
    can act on from a signal handler, and gate.py's recovery path calls it

It is still a real risk on a machine whose keyboard is USB, which is why this
is opt-in (`--close-race-window`) rather than the default. Devices arriving
during the window are unaffected in practice: authorized_default is already 0,
so they are not configured, so they have no interfaces to bind drivers to.

NOT AVAILABLE UNDER --privsep
-----------------------------
drivers_autoprobe is bus-wide, so the gate cannot scope it to a quarantined
device the way it scopes everything else. The privileged gate therefore does
not offer it, supported() returns False, and the daemon falls back -- this time
saying so out loud.
"""

from __future__ import annotations

import atexit
import re
import time
from pathlib import Path
from typing import Callable, List, Optional

from . import sysfs

# Interface directories: <bus>-<port>[.<port>...]:<config>.<interface>
# e.g. 3-1:1.0, 3-10:1.1. The config is always present, as is the interface.
_INTERFACE_RE = re.compile(r":\d+\.\d+$")

# How long to wait for the kernel to create the interface directories after the
# device is authorized. The sysfs write is synchronous, so they are normally
# there the moment it returns; this only covers the pathological case, and it
# is short because every millisecond here is a millisecond of bus-wide autoprobe
# being off.
_INTERFACE_WAIT_S = 0.25
_INTERFACE_POLL_S = 0.005

# Set while autoprobe is held at something other than its original value, so a
# signal handler or a crash path can put it back without having the DeferredBind
# object to hand. None means "we are not holding it".
_autoprobe_original: Optional[int] = None


def interface_dirs(usb_syspath: Path) -> List[Path]:
    """The interface directories belonging to THIS device.

    TWO PATH FORMS -- both must work:

      bus-view (symlink):   /sys/bus/usb/devices/3-1
          interfaces are SIBLINGS: /sys/bus/usb/devices/3-1:1.0
      resolved (pyudev):    /sys/devices/pci.../usb3/3-1
          interfaces are CHILDREN: .../usb3/3-1/3-1:1.0

    The daemon passes the resolved form, so searching only siblings finds
    nothing. We search both.

    An interface of '3-1' is always named '3-1:<cfg>.<intf>', wherever it sits.
    The ':' after the name is what distinguishes '3-1:1.0' from '3-10:1.0' --
    without it the prefix '3-1' would wrongly match '3-10' too.

    Returns [] while the device is unauthorized. That is not a failure; it is
    the kernel behaviour this module is built around.
    """
    name = usb_syspath.name
    prefix = name + ":"
    result: List[Path] = []
    seen: set = set()

    for base in (usb_syspath, usb_syspath.parent):
        try:
            entries = sorted(base.iterdir())
        except OSError:
            continue  # device unplugged, or the path does not exist
        for entry in entries:
            if entry.name in seen:
                continue
            if entry.name.startswith(prefix) and _INTERFACE_RE.search(entry.name):
                if (entry / "authorized").exists():
                    result.append(entry)
                    seen.add(entry.name)
    return result


def supported(usb_syspath: Path = None) -> bool:
    """True if the driverless-authorization mechanism can run here.

    The precondition is about the BUS, not about the device -- which is the
    correction at the heart of this file. A device held at authorized=0 has no
    interface directories to inspect, so asking it anything is meaningless.

    What is actually required:
      * the bus exposes drivers_autoprobe and it reads as an integer
      * the bus exposes drivers_probe, needed to bind on the way back out
      * the active sysfs backend is willing to write them (the privsep gate is
        not, and says so by raising)

    `usb_syspath` is accepted and ignored so existing call sites keep working.
    """
    if not sysfs.backend_supports_bus_wide():
        return False
    if sysfs.get_drivers_autoprobe() is None:
        return False
    return sysfs.DRIVERS_PROBE.exists()


def unsupported_reason() -> str:
    """A sentence explaining why supported() said no, for the operator."""
    if not sysfs.backend_supports_bus_wide():
        return ("the active sysfs backend does not offer bus-wide controls; "
                "this is the case under --privsep, by design, because "
                "drivers_autoprobe cannot be scoped to one device")
    if sysfs.get_drivers_autoprobe() is None:
        return (f"{sysfs.DRIVERS_AUTOPROBE} is not readable; this kernel does "
                "not expose bus-wide autoprobe control")
    if not sysfs.DRIVERS_PROBE.exists():
        return f"{sysfs.DRIVERS_PROBE} does not exist"
    return "no reason; it is supported"


def emergency_restore() -> None:
    """Put drivers_autoprobe back, from anywhere, at any time.

    Registered with atexit before the first write to 0, and safe to call when
    nothing is held. Deliberately swallows nothing: if the restore fails, the
    operator is told exactly what to type, because at that point they may have
    a machine that will not bind a driver to anything.
    """
    global _autoprobe_original
    if _autoprobe_original is None:
        return
    value, _autoprobe_original = _autoprobe_original, None
    try:
        sysfs.set_drivers_autoprobe(value)
    except Exception as exc:  # noqa: BLE001 - last line of defence
        import sys
        print(f"\n!! FAILED to restore drivers_autoprobe: {exc}\n"
              f"!! No USB device will bind a driver until you run, as root:\n"
              f"!!   echo {value} > {sysfs.DRIVERS_AUTOPROBE}\n",
              file=sys.stderr)


atexit.register(emergency_restore)


class DeferredBind:
    """Authorizes a device with no driver bound, and binds later on command.

    Used as a context manager around the quarantine:

        with DeferredBind(dev.syspath) as db:
            db.authorize_device()      # device configured, nothing bound
            ... caller starts the monitor ...
            db.release_interfaces()    # drivers bind, nodes appear, we grab

    On exit every interface is returned to authorized=1 and probed, so an
    approved device is never left half-dead, and drivers_autoprobe is restored
    whether or not anything went wrong.
    """

    def __init__(self, usb_syspath: Path, log: Callable[[str], None] = print,
                 dry_run: bool = False):
        self.syspath = usb_syspath
        self.log = log
        self.dry_run = dry_run
        self.interfaces: List[Path] = []      # discovered AFTER authorization
        self._deauthorized: List[Path] = []
        self._device_authorized = False
        self._holding_autoprobe = False

    # ---------- step 1 ----------

    def __enter__(self) -> "DeferredBind":
        global _autoprobe_original
        if self.dry_run:
            return self
        original = sysfs.get_drivers_autoprobe()
        if original is None:
            raise OSError(f"cannot read {sysfs.DRIVERS_AUTOPROBE}")
        # Record BEFORE writing. If the write itself is what kills us, the
        # atexit handler still knows what to put back.
        _autoprobe_original = original
        try:
            sysfs.set_drivers_autoprobe(0)
        except Exception:
            _autoprobe_original = None
            raise
        self._holding_autoprobe = True
        return self

    # ---------- steps 2 and 3 ----------

    def authorize_device(self) -> None:
        """Power the device on with no driver bound, then pin that per-device.

        Returns with drivers_autoprobe already restored: the bus-wide part of
        the operation is over by the time this call ends, which is what keeps
        the dangerous window down to a couple of sysfs writes.
        """
        if self.dry_run:
            self._device_authorized = True
            return

        try:
            sysfs.set_authorized(self.syspath, 1)
            self._device_authorized = True

            # The interfaces exist now -- this is the whole point, and the
            # reason the old code could never work from where it stood.
            self.interfaces = self._await_interfaces()
            for intf in self.interfaces:
                try:
                    sysfs.set_interface_authorized(intf, 0)
                    self._deauthorized.append(intf)
                except OSError as exc:
                    # An interface we could not close is an interface whose
                    # driver WILL bind as soon as autoprobe comes back. Say so;
                    # quarantine reports incomplete isolation from the grab
                    # side, and this is the same failure seen earlier.
                    self.log(f"  ! {intf.name}: could not hold unbound ({exc})")
        finally:
            # Restore the bus even if authorizing threw. Nothing below this
            # point needs autoprobe off, and leaving it off is the failure mode
            # that matters most.
            self._release_autoprobe()

        self.log(f"  - {self.syspath.name}: authorized with "
                 f"{len(self._deauthorized)}/{len(self.interfaces)} "
                 f"interface(s) held unbound")

    # ---------- step 6 ----------

    def release_interfaces(self) -> None:
        """Allow binding, one interface at a time, with the monitor listening.

        Authorizing an interface is not enough on its own: the kernel sets the
        flag and does not re-probe. The name has to be written to drivers_probe
        for usbhid to actually attach.
        """
        if self.dry_run:
            return
        for intf in list(self._deauthorized):
            try:
                sysfs.set_interface_authorized(intf, 1)
                sysfs.trigger_driver_probe(intf.name)
            except OSError as exc:
                self.log(f"  ! {intf.name}: could not bind ({exc})")
            finally:
                # Removed either way: __exit__ retries the ones still listed,
                # and retrying a path that has vanished is noise.
                self._deauthorized.remove(intf)

    def __exit__(self, exc_type, exc, tb) -> bool:
        # Fail-safe, in this order: the bus first, because a machine that binds
        # no drivers is worse than one device with dead interfaces.
        self._release_autoprobe()
        for intf in list(self._deauthorized):
            try:
                if not self.dry_run:
                    sysfs.set_interface_authorized(intf, 1)
                    sysfs.trigger_driver_probe(intf.name)
            except OSError:
                pass  # device unplugged; the path is gone, no matter
        self._deauthorized.clear()
        return False  # never swallow exceptions

    # ---------- helpers ----------

    def _await_interfaces(self) -> List[Path]:
        """Poll briefly for the interface directories to appear."""
        deadline = time.monotonic() + _INTERFACE_WAIT_S
        while True:
            found = interface_dirs(self.syspath)
            if found or time.monotonic() >= deadline:
                return found
            time.sleep(_INTERFACE_POLL_S)

    def _release_autoprobe(self) -> None:
        if not self._holding_autoprobe:
            return
        self._holding_autoprobe = False
        emergency_restore()


def _write_interface_authorized(intf_dir: Path, value: int) -> None:
    """Kept for callers outside this module; routes through the backend."""
    sysfs.set_interface_authorized(intf_dir, value)
