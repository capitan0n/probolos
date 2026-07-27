"""
Minimal ctypes bindings for the Linux raw-gadget interface.

WHAT THIS IS FOR
----------------
raw-gadget lets a userspace process BE a USB device. Paired with dummy_hcd (a
virtual host controller wired to a virtual device controller on the same
machine), it means an arbitrary USB device -- including a malicious one -- can
be conjured entirely in software, with descriptors chosen byte by byte, and
plugged into the local kernel with no hardware at all.

For Cerberus this is the testbed. It turns "you need a Rubber Ducky to test the
CRITICAL path" into "run this script". Every synthetic device the parser is
tested against in CI can also be made to physically enumerate here, which is
the difference between testing the parser and testing the whole pipeline.

HOW raw-gadget WORKS
--------------------
It is an event loop, not a descriptor you hand over once. You open
/dev/raw-gadget, bind to a UDC, and then the kernel forwards you each control
request of enumeration -- GET_DESCRIPTOR, SET_CONFIGURATION, and so on -- which
YOU answer from Python. So the device's every claim about itself is under your
control, which is exactly what is needed to emulate a device that lies.

This is deliberately low-level. There is no pyusb equivalent for the gadget
side; the interface is raw ioctls. The struct layouts below mirror
include/uapi/linux/usb/raw_gadget.h.

SAFETY
------
A half-initialised gadget can wedge dummy_hcd until the module is reloaded.
Every entry point here is written so that the fd is closed on any exit path,
which releases the gadget, mirroring how gate.py guarantees the USB gate is
reopened however it exits.
"""

from __future__ import annotations

import ctypes
import fcntl
import os
from typing import Optional

# ioctl plumbing. _IOC layout is fixed by the kernel ABI.
_IOC_NONE, _IOC_WRITE, _IOC_READ = 0, 1, 2
_IOC_NRBITS, _IOC_TYPEBITS, _IOC_SIZEBITS = 8, 8, 14
_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS


def _IOC(direction, typ, nr, size):
    return ((direction << _IOC_DIRSHIFT) | (ord(typ) << _IOC_TYPESHIFT) |
            (nr << _IOC_NRSHIFT) | (size << _IOC_SIZESHIFT))


UDC_NAME_LENGTH_MAX = 128
RAW_GADGET_EVENT_CONTROL = 1
USB_RAW_EVENT_INVALID = 0
USB_RAW_EVENT_CONNECT = 1
USB_RAW_EVENT_CONTROL = 2

USB_RAW_EVENTS_TIMEOUT = 0
USB_RAW_IO_FLAGS_ZERO = 0


class UsbRawInit(ctypes.Structure):
    _fields_ = [
        ("driver_name", ctypes.c_uint8 * UDC_NAME_LENGTH_MAX),
        ("device_name", ctypes.c_uint8 * UDC_NAME_LENGTH_MAX),
        ("speed", ctypes.c_uint8),
    ]


# The kernel's struct usb_raw_event is { __u32 type; __u32 length; __u8 data[]; }
# where data[] is a FLEXIBLE array. Two consequences that both caused EINVAL:
#
#   * the _IOC size baked into EVENT_FETCH is sizeof(the header ONLY) = 8,
#     because a flexible member contributes nothing to sizeof. So the request
#     code must be computed from an 8-byte header, not from our buffer.
#   * but the BUFFER we pass must be big enough to receive header + setup
#     packet, or the kernel writes past it. So header and buffer are separate.
class UsbRawEventHeader(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
    ]


class UsbRawEvent(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("data", ctypes.c_uint8 * 8),
    ]


# struct usb_raw_ep_io { __u16 ep; __u16 flags; __u32 length; __u8 data[]; }
# The ep field is required (0 for ep0), and data[] is flexible again, so the
# same header-vs-buffer split as EVENT_FETCH applies.
class UsbRawEp0IoHeader(ctypes.Structure):
    _fields_ = [
        ("ep", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("length", ctypes.c_uint32),
    ]


class UsbRawEp0Io(ctypes.Structure):
    _fields_ = [
        ("ep", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("length", ctypes.c_uint32),
        ("data", ctypes.c_uint8 * 256),
    ]


class UsbCtrlRequest(ctypes.Structure):
    _fields_ = [
        ("bRequestType", ctypes.c_uint8),
        ("bRequest", ctypes.c_uint8),
        ("wValue", ctypes.c_uint16),
        ("wIndex", ctypes.c_uint16),
        ("wLength", ctypes.c_uint16),
    ]


USB_RAW_IOCTL_INIT = _IOC(_IOC_WRITE, 'U', 0, ctypes.sizeof(UsbRawInit))
USB_RAW_IOCTL_RUN = _IOC(_IOC_NONE, 'U', 1, 0)
# _IOC size is the header size (flexible array contributes 0 to the kernel's
# sizeof), even though we hand in a larger buffer to receive the setup packet.
USB_RAW_IOCTL_EVENT_FETCH = _IOC(_IOC_READ, 'U', 2,
                                 ctypes.sizeof(UsbRawEventHeader))
USB_RAW_IOCTL_EP0_WRITE = _IOC(_IOC_WRITE, 'U', 3,
                               ctypes.sizeof(UsbRawEp0IoHeader))
USB_RAW_IOCTL_EP0_READ = _IOC(_IOC_WRITE, 'U', 4,
                              ctypes.sizeof(UsbRawEp0IoHeader))
USB_RAW_IOCTL_CONFIGURE = _IOC(_IOC_NONE, 'U', 5, 0)
USB_RAW_IOCTL_VBUS_DRAW = _IOC(_IOC_WRITE, 'U', 6, ctypes.sizeof(ctypes.c_uint32))

USB_SPEED_FULL = 2
USB_SPEED_HIGH = 3


class RawGadgetError(Exception):
    pass


class RawGadget:
    """
    One emulated USB device.

    Use as a context manager so the fd -- and therefore the gadget -- is always
    released:

        with RawGadget(driver="dummy_udc", device="dummy_hcd") as g:
            g.run_enumeration(descriptors)
    """

    def __init__(self, driver: str = "dummy_udc",
                 device: str = "dummy_udc.0",
                 speed: int = USB_SPEED_HIGH,
                 path: str = "/dev/raw-gadget"):
        self.driver = driver
        self.device = device
        self.speed = speed
        self.path = path
        self.fd: Optional[int] = None

    def __enter__(self) -> "RawGadget":
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def open(self) -> None:
        self.fd = os.open(self.path, os.O_RDWR)
        init = UsbRawInit()
        # driver_name is the UDC driver ("dummy_udc"); device_name is the
        # specific UDC instance ("dummy_udc.0"). Getting these crossed, or
        # passing the host-controller name, is a common cause of EBUSY/EINVAL.
        _copy_name(init.driver_name, self.driver)
        _copy_name(init.device_name, self.device)
        init.speed = self.speed
        self._ioctl(USB_RAW_IOCTL_INIT, init, "INIT")
        try:
            self._ioctl(USB_RAW_IOCTL_RUN, None, "RUN")
        except RawGadgetError as exc:
            if "16" in str(exc) or "busy" in str(exc).lower():
                raise RawGadgetError(
                    "RUN failed: the UDC is already in use. Something is "
                    "holding dummy_udc.0 (often dummy_hcd's own host side, or "
                    "a leftover gadget). Reset with:\n"
                    "    sudo rmmod raw_gadget dummy_hcd\n"
                    "    sudo modprobe dummy_hcd raw_gadget\n"
                    "    cat /sys/class/udc/dummy_udc.0/state   # want 'not attached'"
                ) from exc
            raise

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    # ---- event loop primitives ----

    def fetch_event(self) -> UsbRawEvent:
        # Allocate header + 8 bytes for the setup packet as one buffer, tell
        # the kernel how much room `data` has via `length`, and read the whole
        # thing back into our fixed-layout struct.
        buf = bytearray(ctypes.sizeof(UsbRawEvent))
        # length field (offset 4) = capacity of data[] = 8
        buf[4:8] = (8).to_bytes(4, "little")
        self._ioctl(USB_RAW_IOCTL_EVENT_FETCH, buf, "EVENT_FETCH")
        event = UsbRawEvent.from_buffer_copy(buf)
        return event

    def ep0_write(self, data: bytes) -> None:
        """Answer an IN control request (device -> host)."""
        io = UsbRawEp0Io()
        io.ep = 0
        io.flags = USB_RAW_IO_FLAGS_ZERO
        io.length = min(len(data), 256)
        for i in range(io.length):
            io.data[i] = data[i]
        self._ioctl(USB_RAW_IOCTL_EP0_WRITE, io, "EP0_WRITE")

    def ep0_read(self) -> None:
        """Acknowledge an OUT control request (host -> device)."""
        io = UsbRawEp0Io()
        io.ep = 0
        io.flags = USB_RAW_IO_FLAGS_ZERO
        io.length = 0
        self._ioctl(USB_RAW_IOCTL_EP0_READ, io, "EP0_READ")

    def configure(self) -> None:
        self._ioctl(USB_RAW_IOCTL_CONFIGURE, None, "CONFIGURE")

    def vbus_draw(self, power_ma: int) -> None:
        val = ctypes.c_uint32(power_ma // 2)
        self._ioctl(USB_RAW_IOCTL_VBUS_DRAW, val, "VBUS_DRAW")

    # ---- internals ----

    def _ioctl(self, request, arg, name: str) -> int:
        if self.fd is None:
            raise RawGadgetError(f"{name}: gadget is not open")
        try:
            if arg is None:
                return fcntl.ioctl(self.fd, request)
            return fcntl.ioctl(self.fd, request, arg)
        except OSError as exc:
            raise RawGadgetError(f"{name} failed: {exc}") from exc


def _copy_name(buf, name: str) -> None:
    encoded = name.encode() + b"\x00"
    if len(encoded) > len(buf):
        raise RawGadgetError(f"name too long: {name}")
    for i, byte in enumerate(encoded):
        buf[i] = byte


def parse_setup(event: UsbRawEvent) -> UsbCtrlRequest:
    """Reinterpret an event's 8 data bytes as a control request."""
    req = UsbCtrlRequest()
    ctypes.memmove(ctypes.byref(req), bytes(event.data), 8)
    return req
