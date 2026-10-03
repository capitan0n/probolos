"""
Builders and fixtures shared by more than one test module: descriptor
blobs, fake devices, and a synthetic /dev and /sys tree.
"""

from __future__ import annotations

import os
import shutil
import stat
import struct
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from probolos import descriptors, gate_server, sysfs

# ---------------------------------------------------------------------------
# Builders: synthesise the same bytes the kernel would hand us
# ---------------------------------------------------------------------------

def device_desc(vid, pid, dev_class=0x00, num_configs=1):
    return struct.pack(
        "<BBHBBBBHHHBBBB",
        18, 0x01,          # bLength, DEVICE
        0x0200,            # bcdUSB 2.0
        dev_class, 0, 0,   # class/subclass/protocol
        64,                # bMaxPacketSize0
        vid, pid,
        0x0100,            # bcdDevice
        1, 2, 3,           # string indices
        num_configs,
    )


def config_desc(total_len, num_ifaces, value=1):
    return struct.pack("<BBHBBBBB",
                       9, 0x02, total_len, num_ifaces, value, 0, 0x80, 50)


def iface_desc(num, cls, subcls=0, proto=0, alt=0, n_eps=1):
    return struct.pack("<BBBBBBBBB",
                       9, 0x04, num, alt, n_eps, cls, subcls, proto, 0)


def endpoint_desc():
    return struct.pack("<BBBBHB", 7, 0x05, 0x81, 0x02, 512, 0)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def storage_device_desc(num_configs=1):
    return struct.pack("<BBHBBBBHHHBBBB", 18, 0x01, 0x0200, 0, 0, 0, 64,
                       0x1234, 0x5678, 0x0100, 0, 0, 0, num_configs)


def storage_config_desc(total, n_ifaces=1):
    return struct.pack("<BBHBBBBB", 9, 0x02, total, n_ifaces, 1, 0, 0x80, 50)


def storage_iface_desc(cls=0x08, sub=0x06, proto=0x50, num=0):
    return struct.pack("<BBBBBBBBB", 9, 0x04, num, 0, 1, cls, sub, proto, 0)


def make_widget_device(raw, parse_error=None):
    ds = None
    if parse_error is None:
        ds = descriptors.parse(raw)
    return sysfs.UsbDevice(
        syspath=Path("/sys/devices/pci0000:00/usb1/1-4"), name="1-4",
        vendor_id="1234", product_id="5678", manufacturer="Acme",
        product="Widget", serial="S1", bus=1, device_num=2, speed="480",
        authorized=0, device_class=0, descriptor_set=ds,
        parse_error=parse_error, raw_descriptors=raw,
        removable="removable", instance_id=(1, 2))


STORAGE_BLOB = storage_device_desc() + storage_config_desc(18) + storage_iface_desc()


# ---------------------------------------------------------------------------
# helpers -- descriptor blobs that mirror the real Kingston stick's shape
# ---------------------------------------------------------------------------

def storage_device_blob(*, bcd_usb=0x0210, bcd_device=0x0110,
                        max_packet0=64, max_power_raw=150,
                        include_ss_companion=False,
                        interfaces=None):
    """
    Build a plausible mass-storage descriptor blob.

    Defaults match the USB 2 enumeration of a Kingston DataTraveler 3.0
    (VID 0x0951, PID 0x1666, bcdDevice 0x0110). include_ss_companion=True
    adds SuperSpeed endpoint companion descriptors, matching the USB 3
    enumeration of the same physical stick.
    """
    interfaces = interfaces or [(0x08, 0x06, 0x50)]

    # 18-byte device descriptor
    dev = bytes([
        18, 0x01,
        bcd_usb & 0xFF, (bcd_usb >> 8) & 0xFF,
        0x00, 0x00, 0x00,
        max_packet0,
        0x51, 0x09, 0x66, 0x16,
        bcd_device & 0xFF, (bcd_device >> 8) & 0xFF,
        1, 2, 3,
        1,
    ])

    # per-interface: iface(9) + 2 endpoints(7 each) + optional companions(6 each)
    per_iface = 9 + 2 * 7 + (2 * 6 if include_ss_companion else 0)
    total = 9 + per_iface * len(interfaces)
    cfg = bytes([
        9, 0x02,
        total & 0xFF, (total >> 8) & 0xFF,
        len(interfaces), 1, 0,
        0x80,
        max_power_raw,
    ])

    body = b""
    for n, (cls, sub, proto) in enumerate(interfaces):
        body += bytes([9, 0x04, n, 0, 2, cls, sub, proto, 0])
        body += bytes([7, 0x05, 0x81, 0x02, 0x00, 0x04, 0x00])   # IN bulk
        if include_ss_companion:
            body += bytes([6, 0x30, 0x0F, 0x00, 0x00, 0x00])     # SS companion
        body += bytes([7, 0x05, 0x02, 0x02, 0x00, 0x04, 0x00])   # OUT bulk
        if include_ss_companion:
            body += bytes([6, 0x30, 0x0F, 0x00, 0x00, 0x00])

    return dev + cfg + body


def make_kingston_device(raw, name="1-4", syspath="/sys/devices/pci0000:00/usb1/1-4"):
    return sysfs.UsbDevice(
        syspath=Path(syspath), name=name,
        vendor_id="0951", product_id="1666",
        manufacturer="Kingston", product="DataTraveler 3.0",
        serial="E0D55EA58B39E7C058840855",
        bus=1, device_num=7, speed="480", authorized=0, device_class=0,
        descriptor_set=descriptors.parse(raw), raw_descriptors=raw,
        removable="removable", instance_id=(1, 1000))


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def descriptor_blob(*interfaces, bcd_device=0x0100, vid=0x0951, pid=0x1666):
    """A device descriptor, one configuration, and N interface descriptors."""
    out = bytes([18, 0x01]) + (0x0200).to_bytes(2, "little")
    out += bytes([0, 0, 0, 64])
    out += vid.to_bytes(2, "little") + pid.to_bytes(2, "little")
    out += bcd_device.to_bytes(2, "little") + bytes([1, 2, 3, 1])
    out += bytes([9, 0x02]) + (9 + 9 * len(interfaces)).to_bytes(2, "little")
    out += bytes([len(interfaces), 1, 0, 0x80, 250])
    for number, (cls, sub, proto) in enumerate(interfaces):
        out += bytes([9, 0x04, number, 0, 1, cls, sub, proto, 0])
    return out


def make_device(raw=None, *, manufacturer="Kingston", product="DataTraveler",
                serial="AABBCCDD", removable="removable",
                syspath="/sys/devices/pci0000:00/usb1/1-4", name="1-4"):
    raw = descriptor_blob((0x08, 0x06, 0x50)) if raw is None else raw
    return sysfs.UsbDevice(
        syspath=Path(syspath), name=name, vendor_id="0951", product_id="1666",
        manufacturer=manufacturer, product=product, serial=serial,
        bus=1, device_num=7, speed="480", authorized=0, device_class=0,
        descriptor_set=descriptors.parse(raw), raw_descriptors=raw,
        removable=removable, instance_id=(1, 1000))


class FakeSysfs:
    """A throwaway tree shaped like the real one: real dirs, bus-view symlinks."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="probolos-test-"))
        self.hub = self.root / "devices/pci0000:00/0000:00:14.0/usb1"
        self.hub.mkdir(parents=True)
        (self.hub / "authorized_default").write_text("1\n")
        (self.hub / "authorized").write_text("1\n")
        (self.hub / "idVendor").write_text("1d6b\n")
        (self.hub / "idProduct").write_text("0002\n")
        self.bus = self.root / "bus/usb/devices"
        self.bus.mkdir(parents=True)
        os.symlink(self.hub, self.bus / "usb1")

    def add_device(self, name, parent=None, removable="removable",
                   authorized="0"):
        directory = (parent or self.hub) / name
        directory.mkdir()
        (directory / "authorized").write_text(f"{authorized}\n")
        (directory / "idVendor").write_text("abcd\n")
        (directory / "idProduct").write_text("1234\n")
        (directory / "removable").write_text(f"{removable}\n")
        link = self.bus / name
        if not link.exists():
            os.symlink(directory, link)
        return directory

    def destroy(self):
        shutil.rmtree(self.root, ignore_errors=True)


def power_device_desc(bcd_usb=0x0200, num_configs=1):
    return struct.pack("<BBHBBBBHHHBBBB", 18, 0x01, bcd_usb, 0, 0, 0, 64,
                       0x1234, 0x5678, 0x0100, 1, 2, 3, num_configs)


def power_config_desc(raw_power, attrs=0x80, num_ifaces=1, value=1, total=9):
    return struct.pack("<BBHBBBBB", 9, 0x02, total, num_ifaces, value, 0,
                       attrs, raw_power)


SCSI_DEVICE = "devices/pci0000:00/0000:00:14.0/usb3/3-9/3-9:1.0/host1/" \
              "target1:0:0/1:0:0:0"


_real_stat = os.stat


_real_fstat = os.fstat


class _Tree:
    """A /dev directory and a /sys tree whose /sys/dev/block index is real."""

    def __init__(self, root: Path):
        self.dev = root / "dev"
        self.sys = root / "sys"
        self.dev.mkdir()
        (self.sys / "dev" / "block").mkdir(parents=True)
        self.devnums = {}        # (st_dev, st_ino) of a fake node -> st_rdev

    @property
    def dev_block(self) -> str:
        return str(self.sys / "dev" / "block")

    def disk(self, kernel_name, major, minor, partition_of=None):
        """Register a block device with the fake kernel under major:minor."""
        if partition_of:
            home = self.sys / SCSI_DEVICE / "block" / partition_of / kernel_name
            home.mkdir(parents=True, exist_ok=True)
            (home / "partition").write_text("1\n")
        else:
            home = self.sys / SCSI_DEVICE / "block" / kernel_name
            home.mkdir(parents=True, exist_ok=True)
        os.symlink(os.path.relpath(home, self.dev_block),
                   os.path.join(self.dev_block, f"{major}:{minor}"))

    def node(self, name, major, minor, content=b""):
        """A /dev node that stat reports as block device major:minor."""
        path = self.dev / name
        path.write_bytes(content)
        st = _real_stat(path)
        self.devnums[(st.st_dev, st.st_ino)] = os.makedev(major, minor)
        return str(path)

    def _fake(self, st):
        rdev = self.devnums.get((st.st_dev, st.st_ino))
        if rdev is None:
            return st
        return types.SimpleNamespace(
            st_mode=stat.S_IFBLK | 0o660, st_rdev=rdev, st_dev=st.st_dev,
            st_ino=st.st_ino, st_size=st.st_size)

    def patches(self):
        def fake_stat(path, *a, **kw):
            return self._fake(_real_stat(path, *a, **kw))

        def fake_fstat(fd):
            return self._fake(_real_fstat(fd))

        return [
            mock.patch("os.stat", fake_stat),
            # Python 3.10's pathlib bound os.stat at import time, so patching
            # os.stat alone left Path.stat() -- used by the rdev re-check after
            # open -- reporting the real regular file, on 3.10 only.
            mock.patch.object(Path, "stat",
                              lambda self, *a, **kw: fake_stat(self, *a, **kw)),
            mock.patch("os.fstat", fake_fstat),
            mock.patch.object(sysfs, "_BLOCK_DIR", str(self.dev)),
            mock.patch.object(sysfs, "SYS_DEV_BLOCK", self.dev_block),
            mock.patch.object(gate_server, "BLOCK_PREFIX", str(self.dev) + "/"),
            mock.patch.object(gate_server, "SYS_DEV_BLOCK", self.dev_block),
        ]


class _TreeCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tree = _Tree(Path(tmp.name))
        for patcher in self.tree.patches():
            patcher.start()
            self.addCleanup(patcher.stop)

    def refusal(self, path):
        with self.assertRaises(OSError) as caught:
            os.close(sysfs._DirectBackend().open_block(path))
        return str(caught.exception)


# ---------------------------------------------------------------------------
# The service's stdin
# ---------------------------------------------------------------------------

class ServiceStdin:
    """
    What systemd gives the service as stdin: /dev/null -- not a terminal, and
    EOF to every read. Every attribute looked up on it is recorded, so a test
    can say the terminal was never consulted at all, while code that does
    consult it still gets exactly what the service would get.
    """

    def __init__(self):
        self._null = open(os.devnull)
        self.touches = []

    def release(self):
        self._null.close()

    def __getattr__(self, name):
        self.touches.append(name)
        return getattr(self._null, name)
