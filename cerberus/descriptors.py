"""
Parser for the raw USB descriptor blob exposed at

    /sys/bus/usb/devices/<dev>/descriptors

WHY THIS FILE EXISTS AT ALL
---------------------------
This is the single most important technical detail of the whole project.

When a device is held unauthorized (authorized=0), the kernel *does* read and
cache its descriptors -- but it never calls usb_set_configuration(), so the
interface directories (e.g. 1-4:1.0/) are NEVER created in sysfs.

That means the obvious approach -- "glob the interface dirs and read
bInterfaceClass" -- returns nothing for exactly the devices we care about.
Meanwhile the device-level bDeviceClass is 0x00 ("per-interface") on most real
hardware, so it tells us nothing either.

The `descriptors` binary attribute is the escape hatch: it contains the device
descriptor followed by the full configuration descriptors, including every
interface descriptor, and it IS populated while the device is still blocked.
Parsing it ourselves is what lets Cerberus answer "what does this claim to be?"
*before* granting authorization.  (USBGuard takes the same approach.)

BYTE ORDER
----------
USB descriptors are little-endian on the wire, and the kernel copies them
verbatim without endian conversion, so we unpack with '<'.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List

# Standard descriptor type codes (bDescriptorType)
DESC_DEVICE = 0x01
DESC_CONFIG = 0x02
DESC_INTERFACE = 0x04
DESC_ENDPOINT = 0x05

# Layouts. Every USB descriptor starts with (bLength, bDescriptorType),
# which is what lets us walk the blob without knowing the types in advance.
_DEVICE_FMT = "<BBHBBBBHHHBBBB"   # 18 bytes
_CONFIG_FMT = "<BBHBBBBB"         # 9 bytes
_IFACE_FMT = "<BBBBBBBBB"         # 9 bytes


class DescriptorParseError(ValueError):
    """Raised when the blob is truncated or structurally impossible."""


@dataclass(frozen=True)
class DeviceDescriptor:
    usb_version: int          # bcdUSB, BCD encoded (0x0200 == USB 2.0)
    device_class: int
    device_subclass: int
    device_protocol: int
    vendor_id: int
    product_id: int
    device_version: int       # bcdDevice, the firmware revision
    num_configurations: int


@dataclass(frozen=True)
class InterfaceDescriptor:
    number: int               # bInterfaceNumber
    alternate: int            # bAlternateSetting
    num_endpoints: int
    interface_class: int
    interface_subclass: int
    interface_protocol: int


@dataclass
class ConfigDescriptor:
    value: int                # bConfigurationValue
    num_interfaces: int       # as *declared* by the config descriptor
    attributes: int
    max_power_ma: int         # bMaxPower is in 2mA units
    interfaces: List[InterfaceDescriptor] = field(default_factory=list)


@dataclass
class DescriptorSet:
    device: DeviceDescriptor
    configs: List[ConfigDescriptor] = field(default_factory=list)

    def primary_interfaces(self) -> List[InterfaceDescriptor]:
        """
        Interfaces of the first configuration, alternate setting 0 only.

        Alternate settings are different bandwidth modes of the *same* logical
        interface (typical for webcams and audio); counting them would inflate
        the interface list and produce false "composite device" alarms.
        """
        if not self.configs:
            return []
        return [i for i in self.configs[0].interfaces if i.alternate == 0]

    def interface_classes(self) -> List[int]:
        """Distinct base class codes present, order preserved."""
        seen: List[int] = []
        for iface in self.primary_interfaces():
            if iface.interface_class not in seen:
                seen.append(iface.interface_class)
        return seen

    def declared_interface_mismatch(self) -> bool:
        """
        True if a configuration declares a different number of interfaces than
        it actually contains.  Not proof of anything on its own, but a genuine
        oddity worth surfacing: honest hardware is consistent with itself.
        """
        for cfg in self.configs:
            actual = len({i.number for i in cfg.interfaces})
            if actual != cfg.num_interfaces:
                return True
        return False


def parse(blob: bytes) -> DescriptorSet:
    """
    Parse a full sysfs descriptors blob.

    Structure: [device descriptor][config 0 + its children][config 1 + ...]

    The parse is a TLV walk. Each descriptor announces its own length in the
    first byte, so we advance by that amount and dispatch on the second byte.
    Unknown descriptor types (HID report descriptors 0x21, class-specific audio
    blocks, vendor junk) are skipped harmlessly by the same mechanism -- which
    is important, because a hostile device can put anything in there.
    """
    if len(blob) < 18:
        raise DescriptorParseError(f"blob too short: {len(blob)} bytes")

    (b_length, b_type, bcd_usb, dev_class, dev_subclass, dev_protocol,
     _max_packet0, vid, pid, bcd_device, _i_manu, _i_prod, _i_serial,
     num_configs) = struct.unpack(_DEVICE_FMT, blob[:18])

    if b_type != DESC_DEVICE:
        raise DescriptorParseError(
            f"expected device descriptor (0x01), got 0x{b_type:02x}")
    if b_length != 18:
        raise DescriptorParseError(f"device descriptor bLength={b_length}, expected 18")

    result = DescriptorSet(
        device=DeviceDescriptor(
            usb_version=bcd_usb,
            device_class=dev_class,
            device_subclass=dev_subclass,
            device_protocol=dev_protocol,
            vendor_id=vid,
            product_id=pid,
            device_version=bcd_device,
            num_configurations=num_configs,
        )
    )

    offset = 18
    current: ConfigDescriptor | None = None

    while offset + 2 <= len(blob):
        d_len = blob[offset]
        d_type = blob[offset + 1]

        # A zero length would spin us forever; a hostile device is entitled to
        # send exactly that, so this guard is a security control, not paranoia.
        if d_len < 2:
            raise DescriptorParseError(
                f"invalid bLength={d_len} at offset {offset}")
        if offset + d_len > len(blob):
            # Truncated tail: keep what we parsed rather than throwing it away.
            break

        chunk = blob[offset:offset + d_len]

        if d_type == DESC_CONFIG and d_len >= 9:
            (_l, _t, _total, n_ifaces, cfg_value, _i_cfg,
             attrs, max_power) = struct.unpack(_CONFIG_FMT, chunk[:9])
            current = ConfigDescriptor(
                value=cfg_value,
                num_interfaces=n_ifaces,
                attributes=attrs,
                max_power_ma=max_power * 2,
            )
            result.configs.append(current)

        elif d_type == DESC_INTERFACE and d_len >= 9:
            (_l, _t, i_num, i_alt, i_neps, i_cls,
             i_sub, i_proto, _i_str) = struct.unpack(_IFACE_FMT, chunk[:9])
            iface = InterfaceDescriptor(
                number=i_num,
                alternate=i_alt,
                num_endpoints=i_neps,
                interface_class=i_cls,
                interface_subclass=i_sub,
                interface_protocol=i_proto,
            )
            if current is None:
                # Interface before any configuration: malformed, but we keep it
                # in a synthetic config so the anomaly is visible downstream.
                current = ConfigDescriptor(value=0, num_interfaces=0,
                                           attributes=0, max_power_ma=0)
                result.configs.append(current)
            current.interfaces.append(iface)

        offset += d_len

    return result


def parse_file(path) -> DescriptorSet:
    """Read and parse the sysfs descriptors attribute of one device."""
    with open(path, "rb") as fh:
        return parse(fh.read())
