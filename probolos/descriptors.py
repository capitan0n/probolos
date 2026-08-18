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
Parsing it ourselves is what lets Probolos answer "what does this claim to be?"
*before* granting authorization.  (USBGuard takes the same approach.)

BYTE ORDER
----------
USB descriptors are little-endian on the wire, and the kernel copies them
verbatim without endian conversion, so we unpack with '<'.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

from . import descriptors_safe as _safe

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


# bmAttributes bits in a configuration descriptor
ATTR_SELF_POWERED = 0x40
ATTR_REMOTE_WAKEUP = 0x20


def power_unit_ma(bcd_usb: int) -> int:
    """
    How many milliamps one unit of bMaxPower represents.

    This is the detail that makes naive parsers wrong: bMaxPower is expressed
    in 2 mA units for USB 2.0 and earlier, but in 8 mA units for SuperSpeed
    (USB 3.x). Assuming 2 mA everywhere under-reports every USB 3 device by a
    factor of four -- which would quietly corrupt any rule written about power.
    """
    return 8 if bcd_usb >= 0x0300 else 2


def bus_power_limit_ma(bcd_usb: int) -> int:
    """
    What the bus is actually allowed to supply to one device.

    USB 2.0 permits 5 unit loads of 100 mA; SuperSpeed permits 6 of 150 mA.
    A device declaring more than this is not describing a valid configuration.
    """
    return 900 if bcd_usb >= 0x0300 else 500


@dataclass
class ConfigDescriptor:
    value: int                # bConfigurationValue
    num_interfaces: int       # as *declared* by the config descriptor
    attributes: int
    max_power_ma: int         # already scaled by the correct unit
    max_power_raw: int = 0    # the byte as the device sent it
    power_unit_ma: int = 2    # the multiplier that was applied
    interfaces: List[InterfaceDescriptor] = field(default_factory=list)

    @property
    def self_powered(self) -> bool:
        """The device claims it has its own power supply."""
        return bool(self.attributes & ATTR_SELF_POWERED)

    @property
    def remote_wakeup(self) -> bool:
        return bool(self.attributes & ATTR_REMOTE_WAKEUP)


@dataclass
class DescriptorSet:
    device: DeviceDescriptor
    configs: List[ConfigDescriptor] = field(default_factory=list)

    # Anomalies observed while walking the chain. These exist because the walk
    # now goes through descriptors_safe, which notices things the old inline
    # loop silently swallowed. They are recorded rather than raised so that a
    # merely buggy device still produces a usable report.
    truncated: Optional[str] = None       # chain stopped early; reason
    length_overstated: int = 0            # max (wTotalLength - bytes delivered)

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

    def declared_power_ma(self) -> Optional[int]:
        """Bus power the first configuration asks for, in milliamps."""
        return self.configs[0].max_power_ma if self.configs else None

    def power_span(self) -> Optional[tuple]:
        """(lowest, highest) declared power across configurations."""
        values = [c.max_power_ma for c in self.configs]
        return (min(values), max(values)) if values else None

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
    try:
        head = _safe.take(blob, 0, 18, "device descriptor")
    except _safe.DescriptorParsingError as exc:
        raise DescriptorParseError(str(exc)) from exc

    (b_length, b_type, bcd_usb, dev_class, dev_subclass, dev_protocol,
     _max_packet0, vid, pid, bcd_device, _i_manu, _i_prod, _i_serial,
     num_configs) = struct.unpack(_DEVICE_FMT, head)

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

    current: ConfigDescriptor | None = None
    unit = power_unit_ma(bcd_usb)

    # The walk itself lives in descriptors_safe. That module was written for
    # exactly this job, carries its own regression suite, and was -- until this
    # change -- imported by nothing at all, so none of its protections were in
    # force on the real path. What it adds over the loop that used to be here:
    #
    #   * a bound on the NUMBER of descriptors, not just their sizes, so a
    #     device cannot exhaust us with a flood of minimal two-byte items
    #   * one audited implementation of the bLength >= 2 rule instead of two
    #     copies that could drift apart
    #   * take()-based field access, so a short chunk fails loudly rather than
    #     returning fewer bytes than asked for, which is what Python slicing
    #     does and is the quiet root of this whole class of bug
    #
    # Recoverable errors (a truncated tail) stop the walk and are recorded;
    # non-recoverable ones (bLength < 2, item flood) are refusals, because the
    # walk cannot continue past them at all.
    # Byte offset of the current descriptor within blob[18:]. walk_descriptors
    # yields contiguous chunks, so accumulating their lengths tracks the
    # position exactly -- and the position is what the wTotalLength check needs.
    consumed = 0
    tail = blob[18:]

    try:
        for d_type, chunk in _safe.walk_descriptors(tail):
            offset, consumed = consumed, consumed + len(chunk)
            if d_type == DESC_CONFIG and len(chunk) >= 9:
                (_l, _t, w_total, n_ifaces, cfg_value, _i_cfg,
                 attrs, max_power) = struct.unpack(
                     _CONFIG_FMT, _safe.take(chunk, 0, 9, "config descriptor"))
                # wTotalLength counts THIS configuration descriptor and
                # everything belonging to it, starting at this descriptor --
                # not at the start of the blob. It was being compared against
                # the length of the entire remaining blob, which is wrong in
                # both directions and silently:
                #
                #   * with several configurations the comparison used the sum
                #     of all of them, so an overstatement in any one config was
                #     masked and the rule could effectively never fire;
                #   * with one configuration it happened to be right, which is
                #     why the mistake survived -- the single-config case is the
                #     one anybody tests by hand.
                #
                # Measuring from this descriptor's own offset makes the number
                # mean what the field means. A device that overstates it is
                # describing data it did not send: harmless in itself, but the
                # fingerprint of a descriptor set edited by hand rather than
                # emitted by a vendor toolchain.
                available = len(tail) - offset
                overstated = w_total - available
                if overstated > 0:
                    result.length_overstated = max(result.length_overstated,
                                                   overstated)
                current = ConfigDescriptor(
                    value=cfg_value,
                    num_interfaces=n_ifaces,
                    attributes=attrs,
                    max_power_ma=max_power * unit,
                    max_power_raw=max_power,
                    power_unit_ma=unit,
                )
                result.configs.append(current)

            elif d_type == DESC_INTERFACE and len(chunk) >= 9:
                (_l, _t, i_num, i_alt, i_neps, i_cls,
                 i_sub, i_proto, _i_str) = struct.unpack(
                     _IFACE_FMT, _safe.take(chunk, 0, 9, "interface descriptor"))
                iface = InterfaceDescriptor(
                    number=i_num,
                    alternate=i_alt,
                    num_endpoints=i_neps,
                    interface_class=i_cls,
                    interface_subclass=i_sub,
                    interface_protocol=i_proto,
                )
                if current is None:
                    # Interface before any configuration: malformed, but we keep
                    # it in a synthetic config so the anomaly stays visible.
                    current = ConfigDescriptor(value=0, num_interfaces=0,
                                               attributes=0, max_power_ma=0,
                                               power_unit_ma=unit)
                    result.configs.append(current)
                current.interfaces.append(iface)
    except _safe.DescriptorParsingError as exc:
        if not exc.recoverable:
            raise DescriptorParseError(str(exc)) from exc
        result.truncated = str(exc)

    return result


def parse_file(path) -> DescriptorSet:
    """Read and parse the sysfs descriptors attribute of one device."""
    with open(path, "rb") as fh:
        return parse(fh.read())
