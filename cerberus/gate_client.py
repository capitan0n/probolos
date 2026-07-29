"""
The analyzer's view of the gate: a thin client, holding no privilege.

Everything the unprivileged side needs to affect the physical machine goes
through here, and this class can do nothing on its own -- it only asks the gate
and reports what the gate answered. If this process is compromised, the
attacker inherits exactly this: the ability to ask a heavily-validating root
process to authorize or block a USB device, and to receive read-only input
fds. Not root. That containment is the reason the split exists.
"""

from __future__ import annotations

import array
import os
import socket
from typing import Optional

from . import protocol


class GateError(OSError):
    """
    A failure talking to the gate.

    Subclasses OSError deliberately: the daemon already handles OSError from
    direct sysfs writes (a device removed mid-authorize raises one), and under
    privilege separation the very same situation surfaces here instead. Making
    GateError an OSError means every existing `except OSError` in the daemon
    keeps working identically whether or not privsep is active -- a device that
    vanishes mid-decision is handled the same way in both modes, rather than
    crashing the analyzer in one of them.
    """
    pass


class GateClient:
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def _round_trip(self, req: protocol.Request, expect_fd: bool = False):
        self.sock.sendmsg([req.encode()])
        if expect_fd:
            return self._recv_with_fd()
        data = self.sock.recv(protocol.MAX_MESSAGE)
        if not data:
            raise GateError("gate closed the connection")
        return protocol.Response.decode(data), None

    def _recv_with_fd(self):
        # Room for exactly one fd of ancillary data; the gate never sends more.
        fds = array.array("i")
        msg, ancdata, _flags, _addr = self.sock.recvmsg(
            protocol.MAX_MESSAGE,
            socket.CMSG_LEN(fds.itemsize))
        if not msg:
            raise GateError("gate closed the connection")
        resp = protocol.Response.decode(msg)
        fd = None
        for level, ctype, cdata in ancdata:
            if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
                fds.frombytes(cdata[:len(cdata) - (len(cdata) % fds.itemsize)])
                if fds:
                    fd = fds[0]
        return resp, fd

    # ---- the operations the analyzer is allowed to request ----

    def ping(self) -> bool:
        resp, _ = self._round_trip(protocol.Request(protocol.REQ_PING))
        return resp.ok

    def authorize(self, syspath, value: int) -> None:
        resp, _ = self._round_trip(protocol.Request(
            protocol.REQ_AUTHORIZE, path=str(syspath), value=value))
        if not resp.ok:
            raise GateError(f"authorize failed: {resp.status}: {resp.detail}")

    def set_default(self, hubpath, value: int) -> None:
        resp, _ = self._round_trip(protocol.Request(
            protocol.REQ_SET_DEFAULT, path=str(hubpath), value=value))
        if not resp.ok:
            raise GateError(f"set_default failed: {resp.status}: {resp.detail}")

    def open_block(self, device_path) -> int:
        """Ask the gate to open a whole disk read-only and return the fd."""
        resp, fd = self._round_trip(protocol.Request(
            protocol.REQ_OPEN_BLOCK, path=str(device_path)), expect_fd=True)
        if not resp.ok or fd is None:
            raise GateError(f"open_block failed: {resp.status}: {resp.detail}")
        return fd

    def open_input(self, node_path) -> int:
        """
        Ask the gate to open an input node and return the received fd.

        The analyzer then uses this fd directly for reading events and for the
        EVIOCGRAB ioctl -- both of which work on a read-only fd -- without ever
        having had permission to open the node itself.
        """
        resp, fd = self._round_trip(protocol.Request(
            protocol.REQ_OPEN_INPUT, path=str(node_path)), expect_fd=True)
        if not resp.ok or fd is None:
            raise GateError(f"open_input failed: {resp.status}: {resp.detail}")
        return fd


class GateBackend:
    """
    A sysfs privileged-write backend that routes through the gate.

    Installed via sysfs.install_backend() in the analyzer, so that every
    existing set_authorized / set_authorized_default call in the daemon quietly
    becomes a message to the root gate instead of a direct sysfs write. The
    daemon does not know or care that it is no longer privileged.
    """

    def __init__(self, client: "GateClient"):
        self.client = client

    def authorize(self, syspath, value: int) -> None:
        self.client.authorize(syspath, value)

    def set_default(self, hub, value: int) -> None:
        self.client.set_default(hub, value)

    def open_input(self, node_path) -> int:
        return self.client.open_input(node_path)

    def open_block(self, device_path) -> int:
        return self.client.open_block(device_path)
