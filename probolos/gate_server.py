"""Privileged USB gate.

The analyzer is untrusted. Whole-device, interface and root-hub operations are
separate. Temporary authorization records the kernel directory instance and a
bounded permission to open its input/block nodes. Final admission records no
such permission. Input scope climbs past USB interface nodes to the peripheral.

With media watching enabled (--watch-media), one more scope exists: a storage
host this gate admitted, or found admitted when it started, whose interfaces
are all mass storage. Its whole disks may be opened read-only and it may be
switched OFF, never on, for as long as the same kernel directory instance is
there. That is what lets the analyzer inspect a card inserted into an already
trusted reader, and drop the reader on a policy hit.

One write reaches persistent state: TRUST, which adds a device to the
root-owned trust store so "always" works under --privsep. It is scoped as
tightly as the rest: a device this gate admitted on this connection, asked
for within TRUST_WINDOW of that admission, once, under the fingerprint this
gate took itself before it first switched the device on.

This module plus its protocol and privileged startup/cleanup dependencies form
the userspace privilege boundary. It is not an independent human-approval
service: the analyzer still controls admission policy for unknown devices.
"""

from __future__ import annotations

import array
import os
import re as _re
import socket
import stat
import time
import types
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from . import protocol
# Two more imports into the root process, both for TRUST and both chosen so
# the gate does not carry a second copy of a rule that must agree with the
# analyzer's byte for byte. textsafe is pure string handling (no I/O): the
# serial in a trust key is the textsafe-cleaned one, so the gate cleans it the
# same way or its key never matches. trust holds the key formula and the
# store, whose integrity checks then run here, as root, before every write.
# sysfs is still NOT imported: it would bring the descriptor parser in with it,
# and the gate hashes descriptors without ever parsing them.
from . import textsafe
from . import trust as trust_mod

# The only paths the gate will ever touch. Requests outside these are refused
# regardless of what the analyzer says, because the analyzer is not trusted.
#
# USB device directories are exposed under /sys/bus/usb/devices/ as SYMLINKS
# into the real device tree under /sys/devices/. realpath() follows those
# symlinks, so after resolution a legitimate USB device path begins with
# /sys/devices/ and NOT with the bus prefix. We therefore accept a resolved
# path only if BOTH hold: it is under /sys/devices/, and it is reachable
# through /sys/bus/usb/devices/ (i.e. it really is a USB node, not some other
# device that merely lives under /sys/devices/). This keeps the gate from
# being tricked into writing to an unrelated device while still handling the
# symlinks that the USB subsystem actually uses.
USB_LINK_PREFIX = "/sys/bus/usb/devices/"
USB_REAL_PREFIX = "/sys/devices/"
INPUT_PREFIX = "/dev/input/"
# Where the kernel exposes per-class device homes; its `device` symlink is how
# we climb from a /dev node to the USB device backing it. A module global so
# tests can point the scope check at a synthetic sysfs tree.
SYS_CLASS_PREFIX = "/sys/class/"
# Whole disks only: sda, sdb... never a partition (sda1) and never a mapper or
# loop device. Probolos inspects the medium it was handed, not whatever else
# happens to be attached, and a partition node would let a caller reach into a
# disk it was never asked about.
BLOCK_PREFIX = "/dev/"
_BLOCK_NAME = _re.compile(r"^sd[a-z]+$")
# The kernel's index of block devices by number. Whether a node is a whole disk
# or a partition is read from here, never inferred from its name or minor.
SYS_DEV_BLOCK = "/sys/dev/block"
# Root hubs -- usb1, usb2, ... -- are the only devices that own
# authorized_default. Anything else asking for it is either confused or
# probing, and neither deserves a write.
_ROOT_HUB_NAME = _re.compile(r"^usb\d+$")
# USB interface directories under a device: <device>:<config>.<interface>.
_INTERFACE_NAME = _re.compile(r"^[0-9]+-[0-9.]+:[0-9]+\.[0-9]+$")
_MASS_STORAGE_CLASS = "08"

# ---- TRUST ----
# How long after admission the analyzer may ask for the device to be
# remembered. The daemon asks immediately after admit_device() returns; the
# window only has to cover the ledger write in between. Anything later is not
# the "always" that came with that decision.
TRUST_WINDOW = 60.0
# Most entries the gate will grow the store to. Each REQ_TRUST needs a fresh
# admission, so this is not reachable by an honest user; it bounds what a
# compromised analyzer, admitting and trusting in a loop, can make every later
# load() read. Re-trusting a key already present is always allowed.
MAX_TRUSTED = 1024
# Mirrors sysfs.MAX_DESCRIPTOR_BYTES; duplicated rather than imported for the
# reason given above the imports. The analyzer refuses a larger blob (its key
# is then None), so the gate refusing it too keeps the two in agreement.
MAX_DESCRIPTOR_BYTES = 1024 * 1024
# A sysfs text attribute is at most one page. The analyzer reads idVendor,
# idProduct and serial unbounded; the gate must not. A bound this size still
# covers everything the key keeps (textsafe caps the serial at 126 characters),
# and an attribute that differs past it can only make the keys disagree, which
# refuses.
_ATTR_LIMIT = 4096


class GateServer:
    """
    Runs in the root process. Serves one connected analyzer over a SEQPACKET
    socketpair, one request at a time -- there is exactly one client, so there
    is no session state, no concurrency, and nothing to get wrong there.

    There IS a little state now, and it is worth being explicit about why:
    the two records below are what let the gate distinguish "put back what you
    changed" from "change something you were never given". Both are written
    only by this process, from values read out of sysfs; nothing on the wire
    can add to either. They are per-connection, so a restarted analyzer starts
    with no accumulated permission.

    TRUST adds two more of the same kind: the fingerprint of each device as
    the gate found it before switching it on, and which devices it admitted
    and when. Both are filled from sysfs by this process, and an admission
    record is spent by the first TRUST that names its instance.
    """

    def __init__(self, sock: socket.socket, log=print,
                 watch_media: bool = False, trust_path=None):
        self.sock = sock
        self.log = log
        # Where "always" is written, or None under --no-trust. Comes from the
        # root side's command line, like watch_media: the analyzer cannot
        # point the gate's one persistent write at a file of its choosing.
        self.trust_path = Path(trust_path) if trust_path else None
        # Resolved device path -> (instance, fingerprint), the fingerprint
        # being (key, identity, descriptor_hash) or None if it could not be
        # taken. Taken before the first authorized=1 this gate writes to that
        # instance, so it is what the analyzer read at the uevent -- not
        # whatever the device presents once it is running.
        self._fingerprints: dict = {}
        # Resolved device path -> (instance, monotonic time) for each final
        # admission. What REQ_TRUST may act on, once.
        self._admitted: dict = {}
        # Storage hosts whose media the analyzer may watch: resolved path ->
        # kernel directory instance. Filled only from sysfs, by this process,
        # and only when the operator started it with --watch-media.
        self.watch_media = watch_media
        self._media_hosts: dict = {}
        # Resolved paths of USB devices/interfaces this gate switched ON out of
        # quarantine. Only these may be switched off again.
        self._authorized_here: set = set()
        # Root hub path -> the authorized_default value found there before the
        # gate closed it. Only this value may be written back.
        self._closed_defaults: dict = {}
        self._open_leases: dict = {}
        self._instances: dict = {}
        # Interfaces this gate switched OFF, with the directory instance they
        # had at the time. restore() puts them back.
        #
        # Every other thing the gate can change is undone when the analyzer
        # goes away: whole devices it authorized are re-blocked, root hubs it
        # closed are reopened. Interface authorization was the one operation
        # with no entry in that ledger, so `authorize_interface(intf, 0)`
        # survived the analyzer's death -- a device left configured but with
        # its keyboard half permanently driverless, looking healthy in sysfs,
        # with nothing in the restore path that would ever touch it again.
        # That is a persistent denial of service an analyzer compromise could
        # leave behind, and the lockout-safety argument the rest of this
        # project is built on applies to it exactly as written.
        self._interfaces_off: dict = {}
        if watch_media:
            self._snapshot_media_hosts()


    # ---- path validation: the heart of the security boundary ----

    @staticmethod
    def _safe_usb_path(path: str) -> Optional[Path]:
        """
        Confirm a path names a genuine USB device node, and return it resolved.

        Paths reach us in TWO legitimate forms, and both must be accepted:

          * the bus view, e.g. /sys/bus/usb/devices/5-1 (a symlink), which is
            what sysfs.list_devices produces; and
          * the resolved device-tree path, e.g. /sys/devices/.../5-1, which is
            what pyudev's sys_path produces for the very same device.

        The security requirement is not "which prefix" but "is this actually a
        USB device the kernel recognises". We enforce that structurally: after
        realpath, the path must live under /sys/devices/ AND there must be a
        matching entry under /sys/bus/usb/devices/ whose realpath is identical.
        That second check is what proves it is a USB node and not some other
        device that merely lives under /sys/devices/ -- a caller cannot forge
        it, because only real USB devices are linked from the bus view.

        Traversal is still defeated: realpath collapses ../ first, so
        /sys/bus/usb/devices/../../etc resolves out of /sys/devices/ and fails.
        """
        try:
            resolved = os.path.realpath(path)
        except (OSError, ValueError):
            return None
        # Must resolve into the real device tree and be a directory.
        if not (resolved + "/").startswith(USB_REAL_PREFIX):
            return None
        p = Path(resolved)
        if not p.is_dir():
            return None
        # Prove it is a USB node: some entry in the bus view must resolve to
        # exactly this path. This is the check a forged /sys/devices/ path
        # cannot pass, because only genuine USB devices are linked there.
        bus_view = Path(USB_LINK_PREFIX) / p.name
        try:
            if os.path.realpath(bus_view) == resolved:
                return p
        except OSError:
            pass
        return None

    @staticmethod
    def _safe_input_path(path: str) -> Optional[Path]:
        try:
            resolved = os.path.realpath(path)
        except (OSError, ValueError):
            return None
        if not resolved.startswith(INPUT_PREFIX):
            return None
        p = Path(resolved)
        # Must be an actual event node, not a directory or a symlink target
        # that wandered somewhere unexpected.
        try:
            return p if (p.parent == Path(INPUT_PREFIX)
                         and _re.fullmatch(r"event[0-9]+", p.name)
                         and stat.S_ISCHR(p.stat().st_mode)) else None
        except OSError:
            return None

    @staticmethod
    def _check_block_path(path: str):
        """
        Confirm a path is a whole USB-attached disk node: (node, reason).

        Deliberately narrow: only /dev/sdX, only if the kernel agrees it is a
        block device, and only if the kernel's own record for that device
        number (SYS_DEV_BLOCK) is a whole disk -- no `partition` attribute --
        under the same name. Read-only access to a raw disk is still access to
        every byte on it, so this is the request that most deserves a tight
        check. Mirrors sysfs._check_block_node; the reason travels back in the
        DENIED detail so a refusal says why instead of only that it happened.
        """
        try:
            resolved = os.path.realpath(path)
        except (OSError, ValueError):
            return None, "path cannot be resolved"
        p = Path(resolved)
        block_dir = BLOCK_PREFIX.rstrip("/")
        if str(p.parent) != block_dir:
            return None, f"not a node directly under {block_dir}"
        if not _BLOCK_NAME.match(p.name):
            return None, "not a SCSI disk node (sdX)"
        try:
            st = os.stat(resolved)
        except FileNotFoundError:
            return None, "device node does not exist yet"
        except (OSError, ValueError) as exc:
            return None, f"cannot stat the node: {exc}"
        reason = GateServer._whole_disk_reason(st, p.name)
        if reason:
            return None, reason
        return p, ""

    @staticmethod
    def _whole_disk_reason(st, name: str) -> str:
        """
        Why the inode `st` describes is not the whole disk `name`, or "".

        A stat result rather than a path, so _do_open_block can put the opened
        DESCRIPTOR through the same test (os.fstat): that is the inode the
        analyzer will read. Mirrors sysfs._whole_disk_reason.
        """
        import stat as _stat
        if not _stat.S_ISBLK(st.st_mode):
            return "not a block device"
        number = f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
        try:
            kernel = Path(os.path.realpath(f"{SYS_DEV_BLOCK}/{number}"))
            registered = kernel.is_dir()
            is_partition = registered and os.path.lexists(kernel / "partition")
        except (OSError, ValueError):
            registered, is_partition = False, False
        if not registered:
            return f"the kernel has no block device {number} yet"
        if is_partition:
            return f"the kernel reports {number} is a partition"
        if kernel.name != name:
            return (f"device {number} is {kernel.name} to the kernel, "
                    f"not {name}")
        return ""

    @classmethod
    def _safe_block_path(cls, path: str) -> Optional[Path]:
        return cls._check_block_path(path)[0]

    # ---- kernel-derived peripheral identity and temporary inspection scope ----

    @staticmethod
    def _usb_device_is_blocked(usb_path: Path) -> bool:
        """
        True only if this USB device's `authorized` flag reads exactly 0.

        Missing/unreadable authorized -> False (fail closed: if we cannot prove
        it is blocked, we do not act on it).

        Read through a descriptor pinned on the directory, with O_NOFOLLOW on
        both components. This is the function that answers "is this device
        under quarantine?", and that answer is the whole scoping rule for
        open_input, open_block and interface authorization -- so reading it by
        name meant the gate's central check could be aimed at a file the
        analyzer chose, by planting a symlink at <device>/authorized. The
        writes were pinned and the READ that authorizes them was not, which is
        the wrong half to leave open: a "0" read out of an attacker-chosen file
        turns every scope check in this class into a yes.
        """
        directory_fd = None
        try:
            directory_fd = os.open(usb_path, os.O_RDONLY | os.O_DIRECTORY |
                                   os.O_NOFOLLOW | os.O_CLOEXEC)
            fd = os.open("authorized", os.O_RDONLY | os.O_NOFOLLOW |
                         os.O_CLOEXEC, dir_fd=directory_fd)
            with os.fdopen(fd) as fh:
                return fh.read(8).strip() == "0"
        except OSError:
            return False
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    @classmethod
    def _usb_parent_of(cls, node: Path) -> Optional[Path]:
        """Find the peripheral USB device, never an interface or root hub."""
        try:
            resolved = os.path.realpath(node)
        except (OSError, ValueError):
            return None
        name = Path(resolved).name  # e.g. eventN or sdX

        # /sys/class/input/eventN/device -> ... , /sys/class/block/sdX/device
        for cls_dir in ("input", "block"):
            sys_dev = Path(f"{SYS_CLASS_PREFIX}{cls_dir}/{name}/device")
            if not sys_dev.exists():
                continue
            try:
                cur = Path(os.path.realpath(sys_dev))
            except OSError:
                continue
            # Climb toward the root, checking each ancestor against the bus view.
            while cur != cur.parent and str(cur).startswith(USB_REAL_PREFIX):
                bus_view = Path(USB_LINK_PREFIX) / cur.name
                try:
                    if (":" not in cur.name
                            and not _ROOT_HUB_NAME.fullmatch(cur.name)
                            and bus_view.exists()
                            and os.path.realpath(bus_view) == str(cur)):
                        # Found the USB device. In scope only if it is blocked.
                        return cur
                except OSError:
                    pass
                cur = cur.parent
        return None

    @classmethod
    def _blocked_usb_parent_of(cls, node: Path) -> Optional[Path]:
        parent = cls._usb_parent_of(node)
        return parent if parent and cls._usb_device_is_blocked(parent) else None

    @staticmethod
    def _instance(path):
        st = path.stat()
        return st.st_dev, st.st_ino

    def _owns_instance(self, path):
        try:
            return (str(path) in self._authorized_here
                    and self._instances.get(str(path)) == self._instance(path))
        except OSError:
            return False

    def _open_scope_parent_of(self, node):
        parent = self._usb_parent_of(node)
        if parent is None:
            return None
        if self._usb_device_is_blocked(parent):
            return parent
        if (self._owns_instance(parent)
                and time.monotonic() < self._open_leases.get(str(parent), 0)):
            return parent
        return None

    # ---- media watching: admitted storage hosts ----

    @staticmethod
    def _read_attr_pinned(directory: Path, name: str) -> Optional[str]:
        """One short sysfs read through a pinned directory, never following."""
        directory_fd = None
        try:
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                                   os.O_NOFOLLOW | os.O_CLOEXEC)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory_fd)
            with os.fdopen(fd) as fh:
                return fh.read(64).strip()
        except OSError:
            return None
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    @classmethod
    def _storage_only(cls, usb_path: Path) -> bool:
        """
        Every interface the kernel created is mass storage, and there is one.

        Read from the live interface directories, not from anything the
        analyzer said. A reader that is also a keyboard, a network adapter or
        a vendor function is not a storage host, and reading or dropping it
        on the strength of its storage half is not what this scope is for.
        """
        classes = []
        try:
            names = os.listdir(usb_path)
        except OSError:
            return False
        for name in names:
            if not _INTERFACE_NAME.match(name):
                continue
            classes.append(cls._read_attr_pinned(usb_path / name,
                                                 "bInterfaceClass"))
        return bool(classes) and all(c == _MASS_STORAGE_CLASS for c in classes)

    def _snapshot_media_hosts(self) -> None:
        """Storage hosts already live when the gate starts (the baseline)."""
        try:
            names = os.listdir(USB_LINK_PREFIX)
        except OSError:
            return
        for name in names:
            if ":" in name or _ROOT_HUB_NAME.fullmatch(name):
                continue
            path = self._safe_usb_path(USB_LINK_PREFIX + name)
            if path is None:
                continue
            if (self._read_attr_pinned(path, "authorized") == "1"
                    and self._storage_only(path)):
                try:
                    self._media_hosts[str(path)] = self._instance(path)
                except OSError:
                    continue

    def _media_host(self, path: Path) -> bool:
        """A recorded storage host, same instance, still storage only."""
        if not self.watch_media:
            return False
        try:
            if self._media_hosts.get(str(path)) != self._instance(path):
                return False
        except OSError:
            return False
        return self._storage_only(path)

    def _media_scope_parent_of(self, node):
        parent = self._usb_parent_of(node)
        if parent is not None and self._media_host(parent):
            return parent
        return None

    # ---- request handlers ----

    def _do_authorize(self, req: protocol.Request) -> protocol.Response:
        """Temporary activation; final admission uses a separate operation."""
        return self._change_authorization(req, temporary=True)

    def _do_admit(self, req: protocol.Request) -> protocol.Response:
        if req.value != 1 or req.instance is None:
            return protocol.Response(protocol.ERROR, "admission needs a device instance")
        return self._change_authorization(req, temporary=False)

    def _change_authorization(self, req, temporary):
        if req.value not in (0, 1):
            return protocol.Response(protocol.ERROR, "value must be 0 or 1")
        devpath = self._safe_usb_path(req.path)
        if (devpath is None or ":" in devpath.name
                or _ROOT_HUB_NAME.fullmatch(devpath.name)):
            return protocol.Response(protocol.DENIED, "not a peripheral USB device")
        directory_fd = None
        try:
            directory_fd = os.open(devpath, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC)
            st = os.fstat(directory_fd)
            instance = (st.st_dev, st.st_ino)
            if req.instance is not None and req.instance != instance:
                return protocol.Response(protocol.DENIED, "device changed since inspection")
            read_fd = os.open("authorized", os.O_RDONLY | os.O_NOFOLLOW,
                              dir_fd=directory_fd)
            with os.fdopen(read_fd) as fh:
                blocked = fh.read(8).strip() == "0"
            owned = (str(devpath) in self._authorized_here
                     and self._instances.get(str(devpath)) == instance)
            # A watched storage host may be switched OFF (a media-policy hit),
            # never on. Same instance as recorded, or the port was recycled.
            media_off = (req.value == 0 and temporary
                         and self._media_host(devpath))
            if not blocked and (req.value == 1 or not (owned or media_off)):
                return protocol.Response(protocol.DENIED, "device is outside quarantine")
            if req.value == 1:
                # Only reachable while the device reads 0, through the same
                # pinned directory the write below uses. This is the last
                # moment its descriptors are the ones the analyzer judged, so
                # it is the moment the trust fingerprint is taken.
                self._remember_fingerprint(devpath, directory_fd, instance)
            fd = os.open("authorized", os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
                         dir_fd=directory_fd)
            with os.fdopen(fd, "w") as fh:
                fh.write(str(req.value))
            if req.value == 1 and temporary:
                self._authorized_here.add(str(devpath))
                self._instances[str(devpath)] = instance
                self._open_leases[str(devpath)] = time.monotonic() + 30.0
            else:
                self._authorized_here.discard(str(devpath))
                self._instances.pop(str(devpath), None)
                self._open_leases.pop(str(devpath), None)
            # Only a final admission may be followed by TRUST. Any other
            # write -- a temporary switch-on, a re-block -- means the device
            # is not in the state the decision left it in, so the record goes.
            if req.value == 1 and not temporary:
                self._admitted[str(devpath)] = (instance, time.monotonic())
            else:
                self._admitted.pop(str(devpath), None)
            if req.value == 1 and not temporary and self.watch_media:
                # Admitted by a decision. Whether it is a storage host is
                # judged from its interfaces at every use, not here.
                self._media_hosts[str(devpath)] = instance
            elif req.value == 0:
                self._media_hosts.pop(str(devpath), None)
            return protocol.Response(protocol.OK)
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc))
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    def _do_authorize_interface(self, req: protocol.Request) -> protocol.Response:
        """
        Authorize or deauthorize ONE interface of a device.

        An interface directory (e.g. 1-1:1.0) is linked from the bus view just
        like a device, so _safe_usb_path validates it. Scope is taken from its
        PARENT device: the interface belongs to a device, and it is that device
        which must be under quarantine. This keeps the deferred-bind path from
        becoming a way to bind drivers on hardware that is already in use.
        """
        if req.value not in (0, 1):
            return protocol.Response(protocol.ERROR, "value must be 0 or 1")
        intf = self._safe_usb_path(req.path)
        if intf is None:
            return protocol.Response(
                protocol.DENIED, f"not a USB interface path: {req.path!r}")
        # "1-1:1.0" -> parent device "1-1". An interface name always carries a
        # colon; refusing paths without one keeps this from being used as a
        # second, unscoped route to whole-device authorization.
        if ":" not in intf.name:
            return protocol.Response(
                protocol.DENIED,
                f"not an interface (no configuration:interface suffix): {intf.name}")
        # The parent is VALIDATED, not merely taken. `intf.parent` is plain
        # path arithmetic on a string the analyzer supplied: it was handed
        # straight to _usb_device_is_blocked and _owns_instance, which is the
        # gate trusting the analyzer to describe the very relationship the gate
        # exists to verify. _safe_usb_path is what proves a path is a USB node
        # the kernel recognises (it must be reachable through the bus view,
        # which cannot be forged), and the parent of an interface must clear
        # exactly the same bar as any other device path in this class --
        # including not being an interface itself and not being a root hub,
        # since neither owns interfaces and both would widen the target list.
        parent = self._safe_usb_path(str(intf.parent))
        if (parent is None or ":" in parent.name
                or _ROOT_HUB_NAME.fullmatch(parent.name)):
            return protocol.Response(
                protocol.DENIED,
                f"interface {intf.name} has no valid parent USB device")
        in_scope = (self._usb_device_is_blocked(parent)
                    or self._owns_instance(parent))
        if req.value == 1 and not in_scope:
            return protocol.Response(
                protocol.DENIED,
                "refusing to bind an interface on a device that is not under "
                f"quarantine: {parent.name}")
        # Unbinding one interface of a device is the same denial of service as
        # deauthorizing the whole device, just quieter -- it takes the keyboard
        # half of a working device away and leaves the rest looking healthy. So
        # it is held to the same rule: the parent must be under quarantine, or
        # be a device this gate authorized itself (which is the deferred-bind
        # case, where the device is deliberately on but held driverless).
        if req.value == 0 and not in_scope:
            return protocol.Response(
                protocol.DENIED,
                "refusing to unbind an interface of a device that is neither "
                f"under quarantine nor authorized by this gate: {parent.name}")
        # Written through a descriptor on the interface directory, not by name.
        # _change_authorization was hardened this way and this path was not,
        # which left the gate with two ways to write a sysfs `authorized` and
        # only one of them checking what it was actually writing to. The same
        # reasoning applies here: between _safe_usb_path() above and the write,
        # the interface can be unplugged and the name re-created by whatever
        # enumerates next at that port. Pinning the directory first means the
        # write either lands on the interface that was validated or fails.
        try:
            resp = self._write_authorized_at(intf, req.value)
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc))
        # Recorded only once the write actually landed, and dropped again the
        # moment the interface is authorized, so restore() never writes to an
        # interface it did not switch off.
        if resp.ok:
            if req.value == 0:
                try:
                    self._interfaces_off[str(intf)] = self._instance(intf)
                except OSError:
                    self._interfaces_off[str(intf)] = None
            else:
                self._interfaces_off.pop(str(intf), None)
        return resp

    @staticmethod
    def _write_authorized_at(directory: Path, value: int) -> "protocol.Response":
        """Write `authorized` relative to a held descriptor on `directory`."""
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY |
                               os.O_NOFOLLOW | os.O_CLOEXEC)
        fd: Optional[int]
        try:
            fd = os.open("authorized", os.O_WRONLY | os.O_TRUNC |
                         os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
            try:
                with os.fdopen(fd, "w") as fh:
                    fd = None
                    fh.write(str(value))
            finally:
                if fd is not None:
                    os.close(fd)
            return protocol.Response(protocol.OK)
        finally:
            os.close(directory_fd)

    def _do_set_default(self, req: protocol.Request) -> protocol.Response:
        """
        Close or re-open a root hub's default authorization.

        This is the single most powerful message the protocol carries, and it
        was the least guarded: any USB path, any of three values, no questions.
        Writing 1 here admits every device attached from that moment on without
        a prompt, so a compromised analyzer did not need to defeat Probolos --
        it could ask Probolos's own root half to stand down.

        Three restrictions now, in increasing order of importance:

          * only a ROOT HUB (usbN). authorized_default belongs to nothing else,
            so accepting other paths only ever widened the target list.
          * CLOSING (0) is always allowed and the previous value is remembered.
            Closing is the direction that cannot hurt.
          * OPENING is allowed only back to what this gate found there before
            it closed the hub, and only once. A hub the gate never closed
            cannot be opened at all -- which is the case that matters, because
            it is the one an attacker is in.
        """
        if req.value not in (0, 1, 2):
            return protocol.Response(protocol.ERROR, "value must be 0, 1 or 2")
        hubpath = self._safe_usb_path(req.path)
        if hubpath is None:
            return protocol.Response(protocol.DENIED,
                                     f"path not under {USB_LINK_PREFIX}")
        if not _ROOT_HUB_NAME.match(hubpath.name):
            return protocol.Response(
                protocol.DENIED,
                f"authorized_default belongs to a root hub, not to "
                f"{hubpath.name}")

        # Read and written relative to a descriptor on the hub directory, for
        # the reason given on _write_authorized_at: this is the single most
        # powerful attribute in the protocol and it was the last one still
        # being reached by name after the check that approved it.
        try:
            hub_fd = os.open(hubpath, os.O_RDONLY | os.O_DIRECTORY |
                             os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc))
        try:
            return self._set_default_at(hub_fd, hubpath, req.value)
        finally:
            os.close(hub_fd)

    def _set_default_at(self, hub_fd: int, hubpath: Path,
                        value: int) -> "protocol.Response":
        req = protocol.Request(protocol.REQ_SET_DEFAULT, str(hubpath), value)

        if req.value != 0:
            expected = self._closed_defaults.get(str(hubpath))
            if expected is None:
                return protocol.Response(
                    protocol.DENIED,
                    f"refusing to open {hubpath.name}: this gate never closed "
                    f"it, so there is nothing to restore")
            # gate.py deliberately restores 1 when it found 0, so that the
            # residue of a run that died does not become permanent. Mirror
            # exactly that, and nothing wider.
            allowed = expected if expected != 0 else 1
            if req.value != allowed:
                return protocol.Response(
                    protocol.DENIED,
                    f"refusing to set authorized_default={req.value} on "
                    f"{hubpath.name}: only the previous value ({allowed}) may "
                    f"be restored")

        previous = None
        if req.value == 0:
            try:
                read_fd = os.open("authorized_default",
                                  os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=hub_fd)
                with os.fdopen(read_fd) as fh:
                    previous = int(fh.read(16).strip())
            except (OSError, ValueError):
                # Unreadable, so there is no true previous value to restore.
                # It must NOT stay None: the record below is the only thing
                # that lets this hub be reopened at all, and skipping it left
                # the hub closed permanently -- restore() iterates
                # _closed_defaults, so a hub missing from it is never touched
                # again and no USB device on it binds a driver after the daemon
                # exits. 1 is the same fallback gate.py already uses for a hub
                # found at 0: the only value that leaves the machine usable.
                previous = 1

        write_fd: Optional[int]
        try:
            write_fd = os.open("authorized_default",
                               os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW |
                               os.O_CLOEXEC,
                               dir_fd=hub_fd)
            try:
                with os.fdopen(write_fd, "w") as fh:
                    write_fd = None
                    fh.write(str(req.value))
            finally:
                if write_fd is not None:
                    os.close(write_fd)
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc))

        if req.value == 0:
            # setdefault: the value worth remembering is the one from BEFORE
            # the first close, not whatever a second close would read back (0).
            if previous is not None:
                self._closed_defaults.setdefault(str(hubpath), previous)
        else:
            # Restored. The permission is spent, so a second open is refused
            # exactly like the first would have been on a hub we never closed.
            self._closed_defaults.pop(str(hubpath), None)
        return protocol.Response(protocol.OK)

    def _do_open_input(self, req: protocol.Request):
        """
        Open an input node read-only and return (response, fd).

        Read-only is deliberate and enforced here: the analyzer needs to READ
        events and to EVIOCGRAB (which works on an O_RDONLY fd), and it has no
        legitimate reason to WRITE to an input device. The gate never hands out
        a writable input fd.
        """
        node = self._safe_input_path(req.path)
        if node is None:
            return protocol.Response(protocol.DENIED,
                                     f"not an input node under {INPUT_PREFIX}"), None
        # Scope: the node must be backed by a USB device that is currently under
        # quarantine. This is what refuses /dev/input/event0 for the built-in
        # keyboard -- it is a PS/2 (i8042) device with no USB parent, so it can
        # never be in scope, and a compromised analyzer cannot turn the gate
        # into a system-wide keylogger. An unplugged/authorized device's node
        # is refused too.
        if self._open_scope_parent_of(node) is None:
            return protocol.Response(
                protocol.DENIED,
                "input node is not backed by a USB device under quarantine: "
                f"{node.name}"), None
        fd = None
        try:
            fd = os.open(str(node), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            # The descriptor's own kind, not only its number: a node swapped
            # for a regular file between the check and the open has st_rdev 0
            # both through the fd and through the path, so the numbers agree.
            st = os.fstat(fd)
            if (not stat.S_ISCHR(st.st_mode)
                    or st.st_rdev != node.stat().st_rdev
                    or self._open_scope_parent_of(node) is None):
                os.close(fd)
                return protocol.Response(protocol.DENIED, "device changed during open"), None
            return protocol.Response(protocol.OK, has_fd=True), fd
        except OSError as exc:
            if fd is not None:
                os.close(fd)
            return protocol.Response(protocol.ERROR, str(exc)), None

    def _do_open_block(self, req: protocol.Request):
        """Open a whole disk read-only and pass the descriptor back."""
        node, reason = self._check_block_path(req.path)
        if node is None:
            return protocol.Response(
                protocol.DENIED,
                f"not a whole-disk block device: {req.path!r} ({reason})"), None
        # Scope: the disk must trace back to a USB device under quarantine. An
        # internal SATA/NVMe disk has no USB parent and is refused, so a
        # compromised analyzer cannot read /dev/sda (your system disk) even
        # though it is a valid whole-disk node.
        #
        # Or, with --watch-media, to a storage host being watched: a card
        # inserted into a reader that is already admitted. Read-only still,
        # whole disk still, and only while the reader is storage and nothing
        # else.
        def in_scope():
            return (self._open_scope_parent_of(node) is not None
                    or self._media_scope_parent_of(node) is not None)

        if not in_scope():
            return protocol.Response(
                protocol.DENIED,
                "disk is not backed by a USB device under quarantine: "
                f"{node.name}"), None
        fd = None
        try:
            fd = os.open(str(node), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            # The whole-disk test again, on the DESCRIPTOR. Comparing its
            # st_rdev with a fresh stat of the path proved nothing: a node
            # replaced between the check and the open is replaced for both, so
            # a regular file (st_rdev 0 twice) was passed back as the disk.
            problem = self._whole_disk_reason(os.fstat(fd), node.name)
            if problem or not in_scope():
                os.close(fd)
                detail = "device changed during open"
                if problem:
                    detail += f": {problem}"
                return protocol.Response(protocol.DENIED, detail), None
            return protocol.Response(protocol.OK, has_fd=True), fd
        except OSError as exc:
            if fd is not None:
                os.close(fd)
            return protocol.Response(protocol.ERROR, str(exc)), None

    # ---- trust: keeping "always" under privilege separation ----

    @staticmethod
    def _read_text_at(directory_fd: int, name: str) -> Optional[str]:
        """
        One sysfs text attribute, read as sysfs.read_attr reads it.

        UTF-8 with replacement, then strip(), so the value is the one the
        analyzer got -- but relative to a pinned directory, with O_NOFOLLOW,
        and bounded. None when it cannot be read, as read_attr answers. Both
        sides decode the same way whatever the locale: read_attr used to
        raise on text the locale could not decode, and this mirrored it.
        """
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory_fd)
        except OSError:
            return None
        try:
            with os.fdopen(fd, "rb") as fh:
                raw = fh.read(_ATTR_LIMIT)
        except OSError:
            return None
        return raw.decode("utf-8", errors="replace").strip()

    @classmethod
    def _fingerprint_at(cls, directory_fd: int) -> Optional[tuple]:
        """
        (key, identity, descriptor_hash) of the device behind directory_fd.

        trust.key_for is given the same four values sysfs.load_device would
        give it -- the raw descriptor bytes, idVendor and idProduct as read,
        the serial passed through textsafe -- so the formula exists once and
        the two halves cannot drift apart. The descriptors are hashed and
        never parsed: the root process has no use for what they say, only
        for whether they are the same bytes. None when there is nothing to
        pin trust to, which is exactly when the analyzer's key_for is None.
        """
        try:
            fd = os.open("descriptors", os.O_RDONLY | os.O_NOFOLLOW |
                         os.O_CLOEXEC, dir_fd=directory_fd)
            with os.fdopen(fd, "rb") as fh:
                raw = fh.read(MAX_DESCRIPTOR_BYTES + 1)
            if len(raw) > MAX_DESCRIPTOR_BYTES:
                return None
            vendor = cls._read_text_at(directory_fd, "idVendor")
            product = cls._read_text_at(directory_fd, "idProduct")
            serial = cls._read_text_at(directory_fd, "serial")
        except (OSError, ValueError):
            return None
        if vendor is None or product is None:
            return None     # load_device returns no device at all here
        seen = types.SimpleNamespace(
            vendor_id=vendor, product_id=product,
            serial=textsafe.sanitize(serial).text, raw_descriptors=raw)
        key = trust_mod.key_for(seen)
        if key is None:
            return None
        return key, trust_mod.identity_of(seen), trust_mod.descriptor_hash(seen)

    def _remember_fingerprint(self, devpath: Path, directory_fd: int,
                              instance) -> None:
        """Keep the EARLIEST fingerprint of this instance. Never raises."""
        held = self._fingerprints.get(str(devpath))
        if held is not None and held[0] == instance:
            # Already taken, before an earlier switch-on. A later snapshot
            # would describe a device that has been running, and one that
            # changes what it presents once running is exactly the one whose
            # later testimony must not become what is trusted.
            return
        # A different instance is a different device at the same port; its
        # predecessor's fingerprint means nothing for it.
        self._fingerprints[str(devpath)] = (instance,
                                            self._fingerprint_at(directory_fd))

    def _do_trust(self, req: protocol.Request) -> protocol.Response:
        """
        Remember, in the trust store, a device this gate has just admitted.

        WHY THE ROOT GATE WRITES THIS
        -----------------------------
        The analyzer runs as `nobody`, and the trust store's directory is
        deliberately root-owned: `nobody` is a shared account, so a directory
        it could write is one in which any `nobody` process could forge an
        entry that admits its own device without a prompt. That made "always"
        impossible under --privsep, and a service that asks about its owner's
        own mouse on every plug is a service people switch off.

        WHY THIS ADDS SO LITTLE TO A COMPROMISED ANALYZER
        -------------------------------------------------
        Only the gate's private socketpair can carry this request. It is
        created by the launcher before fork(), so no other process -- other
        `nobody` processes included -- can reach it, which is precisely what
        a writable directory could not promise. A compromised analyzer can
        already admit devices; that is its job. What TRUST adds is
        persistence, and only for:

          * a device this gate admitted on this connection, within
            TRUST_WINDOW, once (the record is spent by the first request
            that names its instance, whether or not it then succeeds);
          * that same kernel directory instance, still authorized now;
          * under the key this gate computed itself, from the device as it
            was before the gate first switched it on. The analyzer's key must
            equal it exactly, so trust cannot be pinned to anything else --
            not to descriptors the device never presented, not to another
            device.

        The label is the only value taken from the request, and only after
        the gate has cleaned it. It is display text for --trusted and is
        never compared when admitting anything.

        Like every handler here, this returns a Response and never raises:
        the gate's restore records must outlive any one request.
        """
        if self.trust_path is None:
            return protocol.Response(protocol.DENIED,
                                     "trust store disabled (--no-trust)")
        devpath = self._safe_usb_path(req.path)
        if (devpath is None or ":" in devpath.name
                or _ROOT_HUB_NAME.fullmatch(devpath.name)):
            return protocol.Response(protocol.DENIED,
                                     "not a peripheral USB device")
        record = self._admitted.get(str(devpath))
        if record is None:
            return protocol.Response(
                protocol.DENIED,
                "this gate has not admitted that device on this connection")
        admitted_instance, admitted_at = record
        if req.instance != admitted_instance:
            return protocol.Response(
                protocol.DENIED, "not the device instance this gate admitted")
        # Spent from here on, whatever the outcome. One admission, one chance
        # to remember it: a failure is not an invitation to try other keys.
        self._admitted.pop(str(devpath), None)
        if time.monotonic() - admitted_at > TRUST_WINDOW:
            return protocol.Response(
                protocol.DENIED,
                f"admitted more than {TRUST_WINDOW:.0f}s ago; trust must come "
                f"with the decision that admitted it")

        # The live directory, pinned: the instance must still be the admitted
        # one (a port recycled since then is different hardware) and it must
        # still be switched on (a device dropped since then -- a media-policy
        # hit, say -- is not one the decision still stands for).
        directory_fd = None
        try:
            directory_fd = os.open(devpath, os.O_RDONLY | os.O_DIRECTORY |
                                   os.O_NOFOLLOW | os.O_CLOEXEC)
            st = os.fstat(directory_fd)
            if (st.st_dev, st.st_ino) != admitted_instance:
                return protocol.Response(protocol.DENIED,
                                         "device changed since admission")
            if self._read_text_at(directory_fd, "authorized") != "1":
                return protocol.Response(protocol.DENIED,
                                         "device is no longer authorized")
        except (OSError, ValueError) as exc:
            return protocol.Response(protocol.ERROR, str(exc))
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

        held = self._fingerprints.get(str(devpath))
        if held is None or held[0] != admitted_instance or held[1] is None:
            return protocol.Response(
                protocol.DENIED,
                "the gate could not fingerprint this device before switching "
                "it on, so there is nothing to pin trust to")
        key, identity, digest = held[1]
        if req.key != key:
            return protocol.Response(protocol.DENIED,
                                     "device fingerprint does not match")

        # Display text, but it ends up in a file root writes and in every
        # terminal that runs --trusted, so the gate cleans it itself: whatever
        # the analyzer sent, no raw ESC, C1 control, DEL or bidi override
        # reaches the file. Cleaned, not refused. The label decides nothing --
        # admission compares the key alone -- and textsafe is not a fixed
        # point on text it has already cut short (a dropped escape resets its
        # combining-mark count), so a label the daemon built from cleaned
        # strings can come back different. Refusing it would lose the
        # person's "always" over a cosmetic difference, with the admission
        # already spent.
        label = textsafe.sanitize(req.label, protocol.MAX_LABEL).text

        now = time.time()
        entry = trust_mod.TrustedDevice.from_raw(key, asdict(
            trust_mod.TrustedDevice(
                key=key, identity=identity, label=label,
                descriptor_hash=digest, trusted_at=now, last_seen=now,
                times_admitted=1, note="", ports=[devpath.name])))
        if entry is None:
            # from_raw is the loader's own validation: an entry it would skip
            # on the next load must not be written in the first place.
            return protocol.Response(protocol.ERROR,
                                     "could not build a valid trust entry")

        # The directory is not this request's to create. Under the shipped
        # unit systemd makes it (StateDirectory=, 0755). Left to atomicio, it
        # would be made here with whatever umask root runs under, and a 0700
        # directory is one the analyzer can read nothing back from -- not
        # this entry, and at its next start not the store at all.
        if not os.path.isdir(self.trust_path.parent):
            return protocol.Response(
                protocol.DENIED,
                f"the trust store's directory {self.trust_path.parent} "
                f"does not exist")

        # Loaded fresh for every request: the store may have been edited by a
        # root-run --remove-trusted since the last one, and its integrity
        # checks should judge the file as it is now. A fresh object also means
        # save() reports its first error, which it otherwise only does once.
        try:
            store = trust_mod.TrustStore(self.trust_path)
        except (OSError, ValueError) as exc:
            return protocol.Response(protocol.ERROR,
                                     f"could not read the trust store: {exc}")
        if store.load_error:
            # Fail closed. Rewriting a store this gate cannot vouch for would
            # either launder what is in it (a group-writable file, a foreign
            # owner) or throw away entries it merely failed to read.
            return protocol.Response(
                protocol.DENIED,
                f"refusing to rewrite a trust store that cannot be vouched "
                f"for: {store.load_error}")
        if key not in store.devices and len(store.devices) >= MAX_TRUSTED:
            return protocol.Response(
                protocol.DENIED,
                f"the trust store already holds {MAX_TRUSTED} devices")
        # Replaced whole, as TrustStore.trust() does in direct mode.
        store.devices[key] = entry
        error = store.save(readable=True)
        if error:
            return protocol.Response(protocol.ERROR,
                                     f"could not save the trust store: {error}")
        self.log(f"[gate] remembered {devpath.name} in {self.trust_path}")
        return protocol.Response(protocol.OK)

    # ---- the loop ----

    def serve_forever(self) -> None:
        try:
            self._serve_requests()
        finally:
            self.restore()

    def restore(self):
        # Interfaces first, and before the devices they belong to are
        # re-blocked: writing `authorized` on an interface of a device that
        # has just been unconfigured fails with ENODEV, and an interface left
        # at 0 is the failure this record exists to prevent.
        for path, instance in list(self._interfaces_off.items()):
            self._interfaces_off.pop(path, None)
            node = Path(path)
            try:
                # The same instance discipline the device paths get: a port
                # recycled since the write means this directory belongs to
                # different hardware, and authorizing an interface of a device
                # nobody inspected is exactly what _do_authorize_interface
                # refuses to do on the request path.
                if instance is not None and self._instance(node) != instance:
                    self.log(f"[gate] not restoring {node.name}: a different "
                             f"device now occupies that path")
                    continue
                self._write_authorized_at(node, 1)
            except OSError as exc:
                self.log(f"[gate] could not re-authorize {node.name}: {exc}")
        for path in list(self._authorized_here):
            if self._owns_instance(Path(path)):
                resp = self._do_authorize(protocol.Request(
                    protocol.REQ_AUTHORIZE, path, 0, self._instances[path]))
                if not resp.ok:
                    self.log(f"[gate] could not re-block {path}: {resp.detail}")
        for path, previous in list(self._closed_defaults.items()):
            resp = self._do_set_default(protocol.Request(
                protocol.REQ_SET_DEFAULT, path, previous or 1))
            if not resp.ok:
                self.log(f"[gate] could not restore {path}: {resp.detail}")

    def _serve_requests(self) -> None:
        while True:
            try:
                data = self.sock.recv(protocol.MAX_MESSAGE + 1)
            except OSError:
                break
            if not data:
                break  # analyzer closed the connection; we are done

            fd_to_send = None
            try:
                req = protocol.Request.decode(data)
            except ValueError as exc:
                try:
                    self._reply(protocol.Response(protocol.ERROR,
                                                  f"bad request: {exc}"))
                except _PeerGone:
                    break
                continue

            # A bug in a handler must not end the gate. This process holds the
            # ONLY record of which hubs it closed and which devices it switched
            # on; if it dies, restore() runs but nothing else does, and the
            # analyzer is left talking to a closed socket. Every handler below
            # is written to return a Response rather than raise, so reaching
            # this except is itself the bug -- which is exactly why it must be
            # caught rather than trusted not to happen.
            try:
                if req.kind == protocol.REQ_PING:
                    resp = protocol.Response(protocol.OK, "pong")
                elif req.kind == protocol.REQ_ADMIT:
                    resp = self._do_admit(req)
                elif req.kind == protocol.REQ_AUTHORIZE:
                    resp = self._do_authorize(req)
                elif req.kind == protocol.REQ_AUTHORIZE_INTERFACE:
                    resp = self._do_authorize_interface(req)
                elif req.kind == protocol.REQ_SET_DEFAULT:
                    resp = self._do_set_default(req)
                elif req.kind == protocol.REQ_OPEN_INPUT:
                    resp, fd_to_send = self._do_open_input(req)
                elif req.kind == protocol.REQ_OPEN_BLOCK:
                    resp, fd_to_send = self._do_open_block(req)
                elif req.kind == protocol.REQ_TRUST:
                    resp = self._do_trust(req)
                else:
                    resp = protocol.Response(protocol.ERROR, "unhandled kind")
            except Exception as exc:   # noqa: BLE001 -- see above
                self.log(f"[gate] handler for {req.kind!r} raised: {exc!r}")
                resp = protocol.Response(protocol.ERROR, "internal gate error")

            peer_gone = False
            try:
                self._reply(resp, fd_to_send)
            except _PeerGone:
                peer_gone = True
            finally:
                # The kernel duplicated the fd into the analyzer on send; our
                # copy is no longer needed and must not leak. In a `finally`
                # because sendmsg can fail -- an analyzer that dies at exactly
                # the wrong moment used to leave the root process holding an
                # open descriptor to a device node for every attempt.
                if fd_to_send is not None:
                    try:
                        os.close(fd_to_send)
                    except OSError:
                        pass
            if peer_gone:
                break

    def _reply(self, resp: protocol.Response, fd: Optional[int] = None) -> None:
        """
        Send one response. A dead peer is a normal end, not a crash.

        sendmsg() to an analyzer that has already exited raises EPIPE, and
        nothing caught it: the exception left _serve_requests, left run_gate,
        and left privsep.start() -- which never reached its os.waitpid(), so
        the root process died with a traceback and the analyzer child was
        orphaned. The analyzer dying between its request and this reply is an
        entirely ordinary way for the tool to shut down (Ctrl-C, a crash, a
        kill), so it must end the serve loop cleanly instead.

        The detail is also bounded. It can contain a path the analyzer chose,
        and a response the analyzer cannot parse is useless to it; MAX_MESSAGE
        is the size its decoder will accept.
        """
        if len(resp.detail) > 1024:
            resp = protocol.Response(resp.status, resp.detail[:1021] + "...",
                                     resp.has_fd)
        payload = resp.encode()
        try:
            if fd is None:
                self.sock.sendmsg([payload])
            else:
                ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                              array.array("i", [fd]))]
                self.sock.sendmsg([payload], ancillary)
        except OSError as exc:
            self.log(f"[gate] analyzer went away before the reply ({exc})")
            raise _PeerGone from exc


class _PeerGone(Exception):
    """The analyzer is no longer reachable. Ends the serve loop, quietly."""


def run_gate(sock: socket.socket, log=print, watch_media: bool = False,
             trust_path=None) -> None:
    """Entry point for the privileged child. Serves until the analyzer exits."""
    GateServer(sock, log=log, watch_media=watch_media,
               trust_path=trust_path).serve_forever()
