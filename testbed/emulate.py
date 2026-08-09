"""
Building emulated USB devices and answering their enumeration.

Two halves:

  * builders that assemble descriptor bytes (device, config, interface...)
  * a responder that runs the raw-gadget event loop and replies to each
    standard control request with those bytes

The builders intentionally mirror the STRUCTURE that probolos/descriptors.py
parses, so a device emulated here and a device in a unit test are the same
shape of thing. The point of the testbed is to prove the parser and rules that
pass in CI also fire when a device physically enumerates.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

from .rawgadget import (RawGadget, UsbCtrlRequest, USB_RAW_EVENT_CONNECT,
                        USB_RAW_EVENT_CONTROL, RawGadgetError, parse_setup)

# Descriptor type codes
DT_DEVICE = 0x01
DT_CONFIG = 0x02
DT_STRING = 0x03
DT_INTERFACE = 0x04
DT_ENDPOINT = 0x05


@dataclass
class Interface:
    cls: int
    subclass: int = 0
    protocol: int = 0
    with_endpoint: bool = True


@dataclass
class EmulatedDevice:
    """A device described entirely in software."""
    vendor_id: int = 0x1d6b          # Linux Foundation, honest default
    product_id: int = 0x0104
    bcd_usb: int = 0x0200
    device_class: int = 0x00
    manufacturer: str = "Probolos"
    product: str = "Testbed Device"
    serial: str = "TB-0001"
    max_power_ma: int = 100
    self_powered: bool = False
    interfaces: List[Interface] = field(default_factory=list)

    # ---- descriptor assembly ----

    def device_descriptor(self) -> bytes:
        return struct.pack(
            "<BBHBBBBHHHBBBB",
            18, DT_DEVICE, self.bcd_usb,
            self.device_class, 0, 0, 64,
            self.vendor_id, self.product_id, 0x0100,
            1, 2, 3,                    # iManufacturer, iProduct, iSerial
            1,                          # bNumConfigurations
        )

    def _interface_block(self, index: int, iface: Interface) -> bytes:
        n_eps = 1 if iface.with_endpoint else 0
        block = struct.pack("<BBBBBBBBB", 9, DT_INTERFACE, index, 0, n_eps,
                            iface.cls, iface.subclass, iface.protocol, 0)
        if iface.with_endpoint:
            # One IN interrupt endpoint is enough to be well-formed.
            block += struct.pack("<BBBBHB", 7, DT_ENDPOINT, 0x81 + index,
                                 0x03, 8, 10)
        return block

    def config_descriptor(self) -> bytes:
        body = b"".join(self._interface_block(i, iface)
                        for i, iface in enumerate(self.interfaces))
        attributes = 0x80 | (0x40 if self.self_powered else 0)
        total = 9 + len(body)
        header = struct.pack("<BBHBBBBB", 9, DT_CONFIG, total,
                             len(self.interfaces), 1, 0,
                             attributes, self.max_power_ma // 2)
        return header + body

    def string_descriptor(self, index: int) -> bytes:
        if index == 0:
            # Language IDs: US English.
            return struct.pack("<BBH", 4, DT_STRING, 0x0409)
        text = {1: self.manufacturer, 2: self.product, 3: self.serial}.get(index, "")
        encoded = text.encode("utf-16-le")
        return bytes([len(encoded) + 2, DT_STRING]) + encoded

    def full_descriptors_blob(self) -> bytes:
        """
        The device + config blob, in the exact form sysfs would expose.

        Handy for feeding probolos.descriptors.parse directly, so the emulated
        device can be checked against the parser without enumerating at all.
        """
        return self.device_descriptor() + self.config_descriptor()


class Responder:
    """
    Runs a raw-gadget through enumeration for an EmulatedDevice.

    Answers the standard GET_DESCRIPTOR / SET_CONFIGURATION requests and stops
    once the host has selected a configuration -- at which point the device is
    fully visible to the kernel and to Probolos.
    """

    def __init__(self, gadget: RawGadget, device: EmulatedDevice, log=print):
        self.g = gadget
        self.dev = device
        self.log = log
        self.configured = False

    def serve(self, max_events: int = 200) -> bool:
        """
        Pump events until configured or exhausted. Returns True if the host
        selected a configuration.
        """
        for _ in range(max_events):
            try:
                event = self.g.fetch_event()
            except RawGadgetError as exc:
                self.log(f"  event fetch stopped: {exc}")
                break

            if event.type == USB_RAW_EVENT_CONNECT:
                self.log("  host connected; enumerating")
                continue
            if event.type != USB_RAW_EVENT_CONTROL:
                continue

            req = parse_setup(event)
            self._handle(req)
            if self.configured:
                return True
        return self.configured

    def _handle(self, req: UsbCtrlRequest) -> None:
        # bRequestType bit 7 set == device-to-host (IN)
        is_in = bool(req.bRequestType & 0x80)
        bRequest = req.bRequest

        if is_in and bRequest == 0x06:          # GET_DESCRIPTOR
            self._get_descriptor(req)
        elif not is_in and bRequest == 0x09:    # SET_CONFIGURATION
            # SET_CONFIGURATION has NO data stage. For a no-data control
            # request raw-gadget completes the status stage in the kernel
            # itself -- we must NOT touch ep0 at all. Writing returned EINVAL
            # (wrong direction) and then EBUSY (ep0 already owned by the
            # kernel's automatic status stage). The correct action is to do
            # nothing here. We also never call the CONFIGURE ioctl: it enables
            # non-ep0 endpoints, and this gadget has none.
            self.configured = True
            self.log("  host selected configuration; device is live")
        elif is_in and bRequest == 0x00:        # GET_STATUS
            self.g.ep0_write(b"\x00\x00")
        else:
            # Anything unmodelled. For an IN request the host wants data we do
            # not have, so send an empty packet. For a no-data OUT request
            # (SET_ADDRESS, SET_FEATURE...) the kernel handles the status stage
            # itself, so we touch nothing -- writing would race the kernel and
            # return EBUSY.
            if is_in:
                self.g.ep0_write(b"")

    def _get_descriptor(self, req: UsbCtrlRequest) -> None:
        desc_type = req.wValue >> 8
        desc_index = req.wValue & 0xFF
        want = req.wLength

        if desc_type == DT_DEVICE:
            data = self.dev.device_descriptor()
        elif desc_type == DT_CONFIG:
            data = self.dev.config_descriptor()
        elif desc_type == DT_STRING:
            data = self.dev.string_descriptor(desc_index)
        else:
            data = b""

        # The host often asks for more than exists; return what we have,
        # truncated to what it asked for. This mirrors real device behaviour
        # and is what the oversized-wLength interrogation probe exploits.
        self.g.ep0_write(data[:want] if want else data)
