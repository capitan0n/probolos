"""
The sysfs layer: everything Probolos knows and everything it can do.

Two responsibilities, kept apart on purpose:

  1. READING   -- what a device says about itself (identity, descriptors)
  2. WRITING   -- the authorization gate itself (authorized / authorized_default)

Nothing here parses, judges, or decides. That belongs in higher layers.
"""

from __future__ import annotations

import re
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import descriptors, textsafe, usbclass

USB_DEVICES = Path("/sys/bus/usb/devices")

# Bus-wide driver binding controls. Unlike everything else in this module these
# are NOT per-device: they belong to the whole usb bus_type, which is precisely
# why touching them is dangerous and why deferred_bind holds them for the
# shortest span it can. Module-level so tests can point them at a temp tree.
DRIVERS_AUTOPROBE = Path("/sys/bus/usb/drivers_autoprobe")
DRIVERS_PROBE = Path("/sys/bus/usb/drivers_probe")

# Root hubs are named usb1, usb2, ... They are the controllers themselves, not
# pluggable devices, and they are where authorized_default lives.
_ROOT_HUB_RE = re.compile(r"^usb\d+$")


def read_attr(devpath: Path, name: str) -> Optional[str]:
    """
    Read one sysfs attribute as text, or None if absent/unreadable.

    Absent attributes are completely normal here (a device with no serial
    number has no `serial` file at all), and a device can be unplugged
    mid-read, so ENOENT/EIO are expected control flow rather than errors.
    """
    try:
        return (devpath / name).read_text().strip()
    except (FileNotFoundError, OSError):
        return None


def read_int_attr(devpath: Path, name: str, base: int = 10) -> Optional[int]:
    raw = read_attr(devpath, name)
    if raw is None:
        return None
    try:
        return int(raw, base)
    except ValueError:
        return None


@dataclass
class UsbDevice:
    """A snapshot of one USB device as sysfs presents it."""

    syspath: Path
    name: str                       # e.g. "1-4" (bus-port path)
    vendor_id: str                  # 4 hex chars, as sysfs gives them
    product_id: str
    manufacturer: Optional[str]     # STRINGS FROM THE DEVICE -- untrusted
    product: Optional[str]
    serial: Optional[str]
    bus: Optional[int]
    device_num: Optional[int]
    speed: Optional[str]
    authorized: Optional[int]
    device_class: Optional[int]
    descriptor_set: Optional[descriptors.DescriptorSet]
    parse_error: Optional[str] = None
    # The unparsed bytes, kept so the ledger can hash the device's testimony
    # exactly as it was given. Hashing our parsed view instead would miss any
    # change in a field the parser ignores -- which is where a device that
    # wants to change quietly would put it.
    raw_descriptors: Optional[bytes] = None
    removable: Optional[str] = None
    # Why the device's own strings had to be cleaned, if they did. These are
    # evidence, not bookkeeping: no legitimate device puts an escape character
    # in its manufacturer string, so a cleaned string with nothing recording
    # WHY would throw away the strongest signal that a descriptor was crafted
    # rather than merely filled in. rules.py turns these into findings.
    string_notes: List[str] = field(default_factory=list)
    string_note_fields: Dict[str, List[str]] = field(default_factory=dict)
    instance_id: Optional[tuple] = None

    # ---------- derived views ----------

    @property
    def interfaces(self) -> List[descriptors.InterfaceDescriptor]:
        if self.descriptor_set is None:
            return []
        return [iface for config in self.descriptor_set.configs
                for iface in config.interfaces]

    @property
    def interface_classes(self) -> List[int]:
        if self.descriptor_set is None:
            return []
        return list(dict.fromkeys(i.interface_class for i in self.interfaces))

    @property
    def kinds(self) -> List[str]:
        """Behavioural buckets this device belongs to (may be more than one)."""
        found: List[str] = []
        for cls in self.interface_classes:
            k = usbclass.kind_of(cls)
            if k not in found:
                found.append(k)
        if not found and self.device_class is not None:
            found.append(usbclass.kind_of(self.device_class))
        return found or [usbclass.KIND_OTHER]

    @property
    def inspection_safe(self) -> bool:
        """Incomplete function lists must never justify early activation."""
        ds = self.descriptor_set
        return bool(ds is not None and not self.parse_error
                    and not ds.truncated and not ds.length_overstated
                    and ds.configs and len(ds.configs) == ds.device.num_configurations
                    and not ds.declared_interface_mismatch())

    @property
    def claims(self) -> List[str]:
        """Human-readable list of what each interface claims to be."""
        return [
            usbclass.describe_interface(i.interface_class,
                                        i.interface_subclass,
                                        i.interface_protocol)
            for i in self.interfaces
        ]

    @property
    def is_root_hub(self) -> bool:
        return bool(_ROOT_HUB_RE.match(self.name))

    def label(self) -> str:
        """Best-effort human label. Remember: these strings are device-supplied."""
        parts = [p for p in (self.manufacturer, self.product) if p]
        return " ".join(parts) if parts else f"{self.vendor_id}:{self.product_id}"


def load_device(syspath: Path) -> Optional[UsbDevice]:
    """
    Build a UsbDevice from a sysfs directory.

    Returns None if this is not a usb_device node (e.g. it is an interface
    directory like 1-4:1.0, which has no idVendor).
    """
    try:
        before = syspath.stat()
    except OSError:
        return None
    vid = read_attr(syspath, "idVendor")
    pid = read_attr(syspath, "idProduct")
    if vid is None or pid is None:
        return None

    desc_set = None
    parse_error = None
    raw = None
    try:
        raw = (syspath / "descriptors").read_bytes()
        desc_set = descriptors.parse(raw)
    except FileNotFoundError:
        parse_error = "no descriptors attribute"
    except descriptors.DescriptorParseError as exc:
        # A device whose descriptors do not parse is itself a finding.
        parse_error = str(exc)
    except OSError as exc:
        parse_error = f"read error: {exc}"

    # Clean the device's own strings HERE, at the one place raw sysfs bytes
    # become Python strings. Cleaning at each display site instead would mean
    # remembering eight destinations -- terminal, kdialog, zenity, tkinter,
    # notification, JSON log, trust store, ledger -- and one of them is not a
    # screen until it is: a `cat probolos.jsonl` three days later would replay
    # an escape-sequence attack in a terminal nobody was guarding.
    #
    # Nothing is lost: raw_descriptors keeps the original bytes, so the ledger
    # still hashes what the device really sent and drift detection is intact.
    _manufacturer = textsafe.sanitize(read_attr(syspath, "manufacturer"))
    _product = textsafe.sanitize(read_attr(syspath, "product"))
    _serial = textsafe.sanitize(read_attr(syspath, "serial"))
    _fields = {
        "iManufacturer": _manufacturer.notes,
        "iProduct": _product.notes,
        "iSerialNumber": _serial.notes,
    }

    try:
        after = syspath.stat()
    except OSError:
        return None
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        return None
    return UsbDevice(
        syspath=syspath,
        name=syspath.name,
        vendor_id=vid,
        product_id=pid,
        manufacturer=_manufacturer.text,
        product=_product.text,
        serial=_serial.text,
        bus=read_int_attr(syspath, "busnum"),
        device_num=read_int_attr(syspath, "devnum"),
        speed=read_attr(syspath, "speed"),
        authorized=read_int_attr(syspath, "authorized"),
        device_class=read_int_attr(syspath, "bDeviceClass", base=16),
        descriptor_set=desc_set,
        parse_error=parse_error,
        raw_descriptors=raw,
        # "fixed" means the port is not user-accessible: a soldered-in webcam,
        # or the built-in keyboard. Probolos must never gate those.
        removable=read_attr(syspath, "removable"),
        string_notes=sorted({n for notes in _fields.values() for n in notes}),
        string_note_fields={k: v for k, v in _fields.items() if v},
        instance_id=(before.st_dev, before.st_ino),
    )


def usb_subsystem_available() -> bool:
    """False on systems with no USB support compiled in, and inside most
    containers, where /sys/bus/usb simply does not exist."""
    return USB_DEVICES.is_dir()


def list_devices() -> List[UsbDevice]:
    """Every usb_device currently known to the kernel."""
    if not usb_subsystem_available():
        return []
    out = []
    for entry in sorted(USB_DEVICES.iterdir()):
        dev = load_device(entry)
        if dev is not None:
            out.append(dev)
    return out


def list_root_hubs() -> List[Path]:
    """Root hub directories -- the ones that own authorized_default."""
    if not usb_subsystem_available():
        return []
    return [p for p in sorted(USB_DEVICES.iterdir()) if _ROOT_HUB_RE.match(p.name)]


# --------------------------------------------------------------------------
# The gate itself
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Privileged-write backend.
#
# By default these operations write sysfs directly, which requires root. When
# privilege separation is active, install_backend() swaps in a backend that
# routes the same calls through the gate over the SEQPACKET socket, so the
# unprivileged analyzer never writes sysfs itself. Callers do not change; only
# the backend does. This is what let the whole daemon move behind the split
# without rewriting its logic.
# --------------------------------------------------------------------------

def _write_attr_pinned(directory, name: str, value: str) -> None:
    """
    Write one sysfs attribute through a descriptor pinned on its directory.

    THE BUG THIS FIXES. Every write below used to be
    `(path / name).write_text(value)`, which is open(..., "w") -- and open()
    FOLLOWS SYMLINKS on the final component. gate_server.py was hardened
    against exactly this and carries the reasoning in full ("between the check
    that approved it and the write, the name can be re-created by whatever
    enumerates next at that port"), but the DIRECT backend -- the one used
    whenever Probolos runs as plain root WITHOUT --privsep, which is the
    default and the documented `sudo python -m probolos` invocation -- was
    never given the same treatment. So the project had two ways to write a
    privileged sysfs attribute and only the less-used one checked what it was
    writing to.

    The consequence is a root arbitrary-file-write: anything that can place a
    symlink at <device>/authorized, <hub>/authorized_default or
    /sys/bus/usb/drivers_autoprobe gets "0" or "1" written, as root, to a file
    of its choosing. sysfs itself is not attacker-writable on a healthy
    system, so this is not remotely triggerable -- but these paths also arrive
    from --allow-port, from pyudev sys_path, and from the test/emulation trees
    (dummy_hcd, raw_gadget, testbed/), where they are ordinary directories.
    A guard that only holds because of where the path happens to come from is
    not a guard.

    O_NOFOLLOW on the attribute refuses a symlink outright; O_DIRECTORY |
    O_NOFOLLOW on the parent refuses one there too; holding the directory fd
    across the write means the write lands on the directory that was opened or
    fails, rather than on whatever took its name meanwhile. O_CLOEXEC because
    this process spawns the storage worker and the dialog backends, and none of
    them have any business inheriting a descriptor onto `authorized`.
    """
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                           os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            with os.fdopen(fd, "w") as fh:
                fd = None          # fdopen owns it from here
                fh.write(value)
        finally:
            if fd is not None:
                os.close(fd)
    finally:
        os.close(directory_fd)


class _DirectBackend:
    """Writes sysfs directly. The original behaviour, used when running as root
    without privilege separation."""

    # Bus-wide operations (drivers_autoprobe, drivers_probe) are available only
    # when we hold real privilege. A backend that cannot offer them declares so
    # here rather than failing at the point of use, because deferred_bind has to
    # know BEFORE it starts whether the mechanism can complete.
    supports_bus_wide = True

    def admit(self, syspath, instance) -> None:
        directory_fd = os.open(syspath, os.O_RDONLY | os.O_DIRECTORY |
                               os.O_CLOEXEC)
        try:
            st = os.fstat(directory_fd)
            if instance != (st.st_dev, st.st_ino):
                raise OSError("device changed since inspection; approval discarded")
            # O_CLOEXEC: this runs in the privileged half, which spawns the
            # storage worker and the dialog backends. A descriptor open on a
            # device's `authorized` attribute must not survive into a child
            # that has no business writing it.
            fd = os.open("authorized", os.O_WRONLY | os.O_TRUNC |
                         os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
            try:
                with os.fdopen(fd, "w") as fh:
                    fd = None      # fdopen owns it from here
                    fh.write("1")
            finally:
                if fd is not None:
                    os.close(fd)
        finally:
            os.close(directory_fd)

    def authorize(self, syspath: Path, value: int) -> None:
        # Pinned rather than by name: see _write_attr_pinned. This is the write
        # that switches a device on, so a symlink here is a root write to a
        # file of the planter's choosing AND a device that never came alive.
        _write_attr_pinned(syspath, "authorized", str(value))

    def authorize_interface(self, intf_dir, value: int) -> None:
        # Interface-level authorization: controls whether the kernel
        # binds a driver to ONE interface, not the whole device.
        _write_attr_pinned(intf_dir, "authorized", str(value))

    def set_default(self, hub: Path, value: int) -> None:
        # The most powerful attribute the tool writes: 1 here admits every
        # device attached from that moment on. It was the last one still being
        # reached by name in this backend.
        _write_attr_pinned(hub, "authorized_default", str(value))

    def open_input(self, node_path) -> int:
        import os
        return os.open(str(node_path), os.O_RDONLY | os.O_NONBLOCK)

    def open_block(self, device_path) -> int:
        import os
        return os.open(str(device_path), os.O_RDONLY | os.O_NONBLOCK)

    def set_drivers_autoprobe(self, value: int) -> None:
        # Bus-wide, and the single most dangerous write in the codebase: left
        # at 0 no device on the machine binds a driver. Pinned for the same
        # reason as the per-device writes -- and here the consequence of a
        # followed symlink is not only the stray root write but a bus that was
        # never actually switched back, with the restore path believing it was.
        _write_attr_pinned(DRIVERS_AUTOPROBE.parent,
                           DRIVERS_AUTOPROBE.name, str(value))

    def trigger_driver_probe(self, name: str) -> None:
        _write_attr_pinned(DRIVERS_PROBE.parent, DRIVERS_PROBE.name, name)


_backend = _DirectBackend()


def install_backend(backend) -> None:
    """Replace the privileged-write backend (used by privsep)."""
    global _backend
    _backend = backend


def set_interface_authorized(intf_dir, value: int) -> None:
    """
    Authorize (1) or deauthorize (0) a single interface of a device.

    An interface at 0 is configured but driverless: for HID that means
    no evdev node is created, so the device has no path into the input
    subsystem. This is what lets us authorize a device without opening
    the grab race. Routed through the active backend, as set_authorized.
    """
    _backend.authorize_interface(intf_dir, value)


def set_authorized(syspath: Path, value: int) -> None:
    """
    Authorize (1) or deauthorize (0) a single device.

    Writing 1 makes the kernel choose and set a configuration, which creates
    the interfaces and binds drivers -- this is the exact instant a keyboard
    becomes able to type. Writing 0 unconfigures it again.

    Routed through the active backend so that under privilege separation the
    write happens in the root gate, not here.
    """
    _backend.authorize(syspath, value)


def admit_device(dev: UsbDevice) -> None:
    """Approve the inspected instance, not whatever now occupies its port."""
    if dev.instance_id is None:
        raise OSError("device instance is unavailable; admission refused")
    _backend.admit(dev.syspath, dev.instance_id)


def get_authorized_default(hub: Path) -> Optional[int]:
    return read_int_attr(hub, "authorized_default")


def backend_supports_bus_wide() -> bool:
    """Whether the active backend will perform bus-wide driver operations."""
    return bool(getattr(_backend, "supports_bus_wide", False))


def get_drivers_autoprobe() -> Optional[int]:
    """Current bus-wide autoprobe setting, or None if unreadable."""
    try:
        return int(DRIVERS_AUTOPROBE.read_text().strip())
    except (OSError, ValueError):
        return None


def set_drivers_autoprobe(value: int) -> None:
    """
    Turn automatic driver binding for the WHOLE usb bus on (1) or off (0).

    This is the only genuinely global switch Probolos ever writes, and it is
    the mechanism that makes a driverless authorization possible: with it at 0,
    the kernel creates a device's interfaces without probing a driver for them,
    so no usbhid, no evdev node, and nothing for a keyboard to type into.

    It is also the most dangerous thing in the codebase. Left at 0, no device
    on the machine binds a driver -- the lockout gate.py exists to prevent, in a
    worse form. Every caller must restore it, and deferred_bind registers an
    atexit restore before it ever writes 0.
    """
    _backend.set_drivers_autoprobe(value)


def trigger_driver_probe(name: str) -> None:
    """
    Ask the usb bus to probe drivers for one device or interface by name.

    Needed because authorizing an interface does not, by itself, cause a rebind:
    the kernel's interface_authorized_store() sets the flag and stops there.
    Writing the name here is what actually makes usbhid attach.
    """
    _backend.trigger_driver_probe(name)


def open_input_node(node_path) -> int:
    """
    Open an input event node and return its file descriptor.

    Routed through the backend for the same reason as the authorize calls: an
    unprivileged analyzer cannot open /dev/input/eventN itself, so under
    privilege separation this becomes a request to the root gate, which opens
    it read-only and passes the descriptor back over SCM_RIGHTS. The caller
    gets a working fd either way and does not need to know which happened.
    """
    return _backend.open_input(node_path)


def open_block_device(device_path) -> int:
    """Open a whole disk read-only, directly or via the gate."""
    return _backend.open_block(device_path)


def set_authorized_default(hub: Path, value: int) -> None:
    """
    Set the default authorization state for devices newly attached to this hub.

    0 = every new device arrives blocked. This is the window Probolos lives in:
    descriptors are read and cached by the kernel, but no configuration is set
    and no driver is bound.

    Note it does NOT retroactively touch devices that are already attached --
    which is precisely the 'only new devices' scope we chose.

    Routed through the active backend, as with set_authorized.
    """
    _backend.set_default(hub, value)
