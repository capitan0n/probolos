"""
The sysfs layer: everything Cerberus knows and everything it can do.

Two responsibilities, kept apart on purpose:

  1. READING   -- what a device says about itself (identity, descriptors)
  2. WRITING   -- the authorization gate itself (authorized / authorized_default)

Nothing here parses, judges, or decides. That belongs in higher layers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from . import descriptors, usbclass

USB_DEVICES = Path("/sys/bus/usb/devices")

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

    # ---------- derived views ----------

    @property
    def interfaces(self) -> List[descriptors.InterfaceDescriptor]:
        if self.descriptor_set is None:
            return []
        return self.descriptor_set.primary_interfaces()

    @property
    def interface_classes(self) -> List[int]:
        if self.descriptor_set is None:
            return []
        return self.descriptor_set.interface_classes()

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

    return UsbDevice(
        syspath=syspath,
        name=syspath.name,
        vendor_id=vid,
        product_id=pid,
        manufacturer=read_attr(syspath, "manufacturer"),
        product=read_attr(syspath, "product"),
        serial=read_attr(syspath, "serial"),
        bus=read_int_attr(syspath, "busnum"),
        device_num=read_int_attr(syspath, "devnum"),
        speed=read_attr(syspath, "speed"),
        authorized=read_int_attr(syspath, "authorized"),
        device_class=read_int_attr(syspath, "bDeviceClass", base=16),
        descriptor_set=desc_set,
        parse_error=parse_error,
        raw_descriptors=raw,
        # "fixed" means the port is not user-accessible: a soldered-in webcam,
        # or the built-in keyboard. Cerberus must never gate those.
        removable=read_attr(syspath, "removable"),
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

class _DirectBackend:
    """Writes sysfs directly. The original behaviour, used when running as root
    without privilege separation."""

    def authorize(self, syspath: Path, value: int) -> None:
        (syspath / "authorized").write_text(str(value))

    def authorize_interface(self, intf_dir, value: int) -> None:
        # Interface-level authorization: controls whether the kernel
        # binds a driver to ONE interface, not the whole device.
        (intf_dir / "authorized").write_text(str(value))

    def set_default(self, hub: Path, value: int) -> None:
        (hub / "authorized_default").write_text(str(value))

    def open_input(self, node_path) -> int:
        import os
        return os.open(str(node_path), os.O_RDONLY | os.O_NONBLOCK)

    def open_block(self, device_path) -> int:
        import os
        return os.open(str(device_path), os.O_RDONLY)


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


def get_authorized_default(hub: Path) -> Optional[int]:
    return read_int_attr(hub, "authorized_default")


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

    0 = every new device arrives blocked. This is the window Cerberus lives in:
    descriptors are read and cached by the kernel, but no configuration is set
    and no driver is bound.

    Note it does NOT retroactively touch devices that are already attached --
    which is precisely the 'only new devices' scope we chose.

    Routed through the active backend, as with set_authorized.
    """
    _backend.set_default(hub, value)
