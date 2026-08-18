"""
The privileged gate. This is the ONLY code that runs as root.

Read this file whole. It is meant to be short enough that you can, and its
shortness is a security property, not a style preference: the trusted computing
base of the whole tool is this file plus the kernel. Everything clever --
rules, timing, the ledger, payload reconstruction -- lives in the unprivileged
analyzer, where a bug is a bug and not a root compromise.

WHAT IT WILL DO
    - write authorized / authorized_default under /sys/bus/usb/devices
    - open an input node under /dev/input read-only and hand back the fd
    - answer a ping

WHAT IT WILL NOT DO, EVER
    - parse a descriptor, run a rule, read a keystroke, touch the ledger,
      open a network socket, read a config file, or act on any path outside
      the two directories below.

Every request is checked against a fixed path prefix before the syscall. The
analyzer is treated as untrusted input, because the entire value of the split
is that a compromised analyzer cannot escalate. A message asking to write
"/etc/shadow" is refused here, not trusted to be well-intentioned.

Beyond "is this a real USB/input/block node", the gate also enforces SCOPE: it
acts only on a USB device the kernel currently reports as blocked
(authorized=0), and on input/block nodes whose USB parent is such a device.
This is derived from the kernel, not from the analyzer's claims, so a
compromised analyzer cannot open the built-in keyboard, read the system disk,
or disturb a device you are actively using -- even with otherwise valid paths.

TWO HOLES IN THAT SCOPE, NOW CLOSED
-----------------------------------
The paragraph above was the claim; the code did not fully implement it.

  1. DEAUTHORIZATION WAS UNSCOPED. `value=0` was accepted for any valid USB
     path, on the reasoning that "tightening is never the risk". It is: the
     device you are actively using is exactly the one an attacker wants
     switched off. A compromised analyzer could send authorize(<your USB
     keyboard>, 0) -- or, worse, unbind one interface of it -- and kill
     hardware the gate had never been asked about. That contradicts the
     sentence above, which promises the opposite.

     The gate therefore remembers which devices IT authorized out of
     quarantine, and will switch off only those, or something already off
     (a no-op). Everything else is refused.

  2. authorized_default WAS COMPLETELY UNSCOPED. It is the global switch the
     whole tool rests on: setting it back to 1 means every device attached
     afterwards is admitted with no question asked. Any path was accepted and
     any value was written, so the cheapest possible attack on Probolos was to
     ask its own root half to turn it off -- no exploit needed beyond a
     compromised analyzer, which is precisely the threat the split exists for.

     Now: only a root hub (usbN) is accepted; 0 is always allowed (closing is
     never the risk); and the gate will re-open a hub ONLY to the value it
     itself read there before closing it. A hub the gate never closed cannot
     be opened by the analyzer at all.

Both records live in this process and are never taken from the wire, so a
compromised analyzer cannot widen its scope by asserting anything.
"""

from __future__ import annotations

import array
import os
import socket
from pathlib import Path
from typing import Optional

from . import protocol

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
import re as _re
_BLOCK_NAME = _re.compile(r"^sd[a-z]+$")
# Root hubs -- usb1, usb2, ... -- are the only devices that own
# authorized_default. Anything else asking for it is either confused or
# probing, and neither deserves a write.
_ROOT_HUB_NAME = _re.compile(r"^usb\d+$")


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
    """

    def __init__(self, sock: socket.socket, log=print):
        self.sock = sock
        self.log = log
        # Resolved paths of USB devices/interfaces this gate switched ON out of
        # quarantine. Only these may be switched off again.
        self._authorized_here: set = set()
        # Root hub path -> the authorized_default value found there before the
        # gate closed it. Only this value may be written back.
        self._closed_defaults: dict = {}

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
        except OSError:
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
        except OSError:
            return None
        if not resolved.startswith(INPUT_PREFIX):
            return None
        p = Path(resolved)
        # Must be an actual event node, not a directory or a symlink target
        # that wandered somewhere unexpected.
        return p if (p.exists() and p.name.startswith("event")) else None

    @staticmethod
    def _safe_block_path(path: str) -> Optional[Path]:
        """
        Confirm a path is a whole USB-attached disk node.

        Deliberately narrow: only /dev/sdX with no partition suffix, and only
        if the kernel agrees it is a block device. Read-only access to a raw
        disk is still access to every byte on it, so this is the request that
        most deserves a tight check.
        """
        import stat as _stat
        try:
            resolved = os.path.realpath(path)
        except OSError:
            return None
        p = Path(resolved)
        if p.parent != Path("/dev") or not _BLOCK_NAME.match(p.name):
            return None
        try:
            if not _stat.S_ISBLK(os.stat(resolved).st_mode):
                return None
        except OSError:
            return None
        return p

    # ---- scope: the gate acts only on a device that is genuinely blocked ----
    #
    # The path checks above prove "this is a real USB / input / block node". They
    # do NOT prove "this is the device the analyzer is supposed to be inspecting
    # right now". Without that second question the boundary is far weaker than it
    # looks: a compromised analyzer could ask the gate to open /dev/input/event0
    # (your built-in keyboard) for a system-wide keylogger, read /dev/sda, or
    # deauthorize a device you are actively using -- all with valid paths.
    #
    # The invariant that closes this is: the gate only ever acts on a USB device
    # whose kernel `authorized` flag is currently 0. That is precisely the set of
    # devices Probolos is holding for a decision. A device you are using is
    # authorized=1 and is refused; the built-in keyboard is not a USB device at
    # all and is refused; a raw disk whose USB parent is authorized=1 is refused.
    #
    # Crucially this is derived from the KERNEL, not asserted by the analyzer, so
    # a compromised analyzer cannot widen its own scope by lying.

    @staticmethod
    def _usb_device_is_blocked(usb_path: Path) -> bool:
        """
        True only if this USB device's `authorized` flag reads exactly 0.

        Missing/unreadable authorized -> False (fail closed: if we cannot prove
        it is blocked, we do not act on it).
        """
        try:
            raw = (usb_path / "authorized").read_text().strip()
        except OSError:
            return False
        return raw == "0"

    @classmethod
    def _blocked_usb_parent_of(cls, node: Path) -> Optional[Path]:
        """
        Walk up from a /dev node's sysfs home to the USB device backing it, and
        return that USB device path ONLY if it is currently blocked.

        A /dev/input/eventN or /dev/sdX has a sysfs directory under
        /sys/class/... whose `device` symlink chain climbs the device tree. A
        USB-backed node's chain passes through a directory that the bus view
        (/sys/bus/usb/devices/) also links to. A PS/2 keyboard (i8042) or a SATA
        disk has no such USB ancestor, so this returns None and the node is
        refused -- which is exactly what keeps the built-in keyboard off-limits.
        """
        try:
            resolved = os.path.realpath(node)
        except OSError:
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
                    if (bus_view.exists()
                            and os.path.realpath(bus_view) == str(cur)):
                        # Found the USB device. In scope only if it is blocked.
                        return cur if cls._usb_device_is_blocked(cur) else None
                except OSError:
                    pass
                cur = cur.parent
        return None

    # ---- request handlers ----

    def _do_authorize(self, req: protocol.Request) -> protocol.Response:
        if req.value not in (0, 1):
            return protocol.Response(protocol.ERROR, "value must be 0 or 1")
        devpath = self._safe_usb_path(req.path)
        if devpath is None:
            # Include the exact path and its resolved form in the denial, so a
            # rejected request can be diagnosed instead of guessed at.
            resolved = os.path.realpath(req.path) if req.path else "(empty)"
            return protocol.Response(
                protocol.DENIED,
                f"not a USB device path: {req.path!r} -> {resolved!r}")
        # Scope, switching ON: only a device that is currently blocked. This
        # stops a compromised analyzer re-authorizing -- or churning -- a
        # device you are actively using.
        if req.value == 1 and not self._usb_device_is_blocked(devpath):
            return protocol.Response(
                protocol.DENIED,
                "refusing to authorize a device that is not under quarantine "
                f"(authorized != 0): {devpath.name}")

        # Scope, switching OFF. This used to be unconditional, on the reasoning
        # that tightening cannot hurt. It can: the device an attacker most
        # wants switched off is the one you are using, and "deauthorize the
        # user's USB keyboard" is a one-message denial of service that every
        # other check here was written to prevent.
        #
        # The legitimate need is narrow and can be stated exactly: the daemon
        # authorizes a device for quarantine or a storage read and must be able
        # to put it straight back. So the gate allows switching off only what
        # it switched on, plus anything already off (where the write is a
        # no-op that keeps the daemon's "make the state explicit" calls
        # working).
        if req.value == 0 and str(devpath) not in self._authorized_here:
            if not self._usb_device_is_blocked(devpath):
                return protocol.Response(
                    protocol.DENIED,
                    "refusing to deauthorize a device this gate did not "
                    f"authorize: {devpath.name}")
        try:
            (devpath / "authorized").write_text(str(req.value))
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc))
        # Recorded only after the write succeeded, so a failed authorization
        # never grants the right to deauthorize something.
        if req.value == 1:
            self._authorized_here.add(str(devpath))
        else:
            self._authorized_here.discard(str(devpath))
        return protocol.Response(protocol.OK)

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
        parent = intf.parent
        in_scope = (self._usb_device_is_blocked(parent)
                    or str(parent) in self._authorized_here)
        if req.value == 1 and not self._usb_device_is_blocked(parent):
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
        try:
            (intf / "authorized").write_text(str(req.value))
            return protocol.Response(protocol.OK)
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc))

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

        attr = hubpath / "authorized_default"

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
                previous = int(attr.read_text().strip())
            except (OSError, ValueError):
                previous = None

        try:
            attr.write_text(str(req.value))
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
        if self._blocked_usb_parent_of(node) is None:
            return protocol.Response(
                protocol.DENIED,
                "input node is not backed by a USB device under quarantine: "
                f"{node.name}"), None
        try:
            fd = os.open(str(node), os.O_RDONLY | os.O_NONBLOCK)
            return protocol.Response(protocol.OK, has_fd=True), fd
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc)), None

    def _do_open_block(self, req: protocol.Request):
        """Open a whole disk read-only and pass the descriptor back."""
        node = self._safe_block_path(req.path)
        if node is None:
            return protocol.Response(
                protocol.DENIED,
                f"not a whole-disk block device: {req.path!r}"), None
        # Scope: the disk must trace back to a USB device under quarantine. An
        # internal SATA/NVMe disk has no USB parent and is refused, so a
        # compromised analyzer cannot read /dev/sda (your system disk) even
        # though it is a valid whole-disk node.
        if self._blocked_usb_parent_of(node) is None:
            return protocol.Response(
                protocol.DENIED,
                "disk is not backed by a USB device under quarantine: "
                f"{node.name}"), None
        try:
            fd = os.open(str(node), os.O_RDONLY)
            return protocol.Response(protocol.OK, has_fd=True), fd
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc)), None

    # ---- the loop ----

    def serve_forever(self) -> None:
        while True:
            try:
                data = self.sock.recv(protocol.MAX_MESSAGE)
            except OSError:
                break
            if not data:
                break  # analyzer closed the connection; we are done

            fd_to_send = None
            try:
                req = protocol.Request.decode(data)
            except ValueError as exc:
                self._reply(protocol.Response(protocol.ERROR,
                                              f"bad request: {exc}"))
                continue

            if req.kind == protocol.REQ_PING:
                resp = protocol.Response(protocol.OK, "pong")
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
            else:
                resp = protocol.Response(protocol.ERROR, "unhandled kind")

            try:
                self._reply(resp, fd_to_send)
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

    def _reply(self, resp: protocol.Response, fd: Optional[int] = None) -> None:
        payload = resp.encode()
        if fd is None:
            self.sock.sendmsg([payload])
        else:
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                          array.array("i", [fd]))]
            self.sock.sendmsg([payload], ancillary)


def run_gate(sock: socket.socket, log=print) -> None:
    """Entry point for the privileged child. Serves until the analyzer exits."""
    GateServer(sock, log=log).serve_forever()
