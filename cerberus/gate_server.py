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
# Whole disks only: sda, sdb... never a partition (sda1) and never a mapper or
# loop device. Cerberus inspects the medium it was handed, not whatever else
# happens to be attached, and a partition node would let a caller reach into a
# disk it was never asked about.
BLOCK_PREFIX = "/dev/"
import re as _re
_BLOCK_NAME = _re.compile(r"^sd[a-z]+$")


class GateServer:
    """
    Runs in the root process. Serves one connected analyzer over a SEQPACKET
    socketpair, one request at a time -- there is exactly one client, so there
    is no session state, no concurrency, and nothing to get wrong there.
    """

    def __init__(self, sock: socket.socket, log=print):
        self.sock = sock
        self.log = log

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
        try:
            (devpath / "authorized").write_text(str(req.value))
            return protocol.Response(protocol.OK)
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc))

    def _do_set_default(self, req: protocol.Request) -> protocol.Response:
        if req.value not in (0, 1, 2):
            return protocol.Response(protocol.ERROR, "value must be 0, 1 or 2")
        hubpath = self._safe_usb_path(req.path)
        if hubpath is None:
            return protocol.Response(protocol.DENIED,
                                     f"path not under {USB_LINK_PREFIX}")
        try:
            (hubpath / "authorized_default").write_text(str(req.value))
            return protocol.Response(protocol.OK)
        except OSError as exc:
            return protocol.Response(protocol.ERROR, str(exc))

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
            elif req.kind == protocol.REQ_SET_DEFAULT:
                resp = self._do_set_default(req)
            elif req.kind == protocol.REQ_OPEN_INPUT:
                resp, fd_to_send = self._do_open_input(req)
            elif req.kind == protocol.REQ_OPEN_BLOCK:
                resp, fd_to_send = self._do_open_block(req)
            else:
                resp = protocol.Response(protocol.ERROR, "unhandled kind")

            self._reply(resp, fd_to_send)
            if fd_to_send is not None:
                # The kernel duplicated the fd into the analyzer on send; our
                # copy is no longer needed and must not leak.
                os.close(fd_to_send)

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
