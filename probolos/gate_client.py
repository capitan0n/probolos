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
import threading
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
        self._lock = threading.RLock()

    def _round_trip(self, req: protocol.Request, expect_fd: bool = False):
        # Watchdog and daemon share this socket; replies must not cross threads.
        with self._lock:
            try:
                return self._exchange(req, expect_fd)
            except BaseException:
                # A signal can interrupt after send but before recv. Never
                # consume that stale response as the next operation's reply.
                self.sock.close()
                raise

    def _exchange(self, req, expect_fd=False):
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

    def admit(self, syspath, instance) -> None:
        resp, _ = self._round_trip(protocol.Request(
            protocol.REQ_ADMIT, path=str(syspath), value=1, instance=instance))
        if not resp.ok:
            raise GateError(f"admit failed: {resp.status}: {resp.detail}")

    def authorize(self, syspath, value: int) -> None:
        resp, _ = self._round_trip(protocol.Request(
            protocol.REQ_AUTHORIZE, path=str(syspath), value=value))
        if not resp.ok:
            raise GateError(f"authorize failed: {resp.status}: {resp.detail}")

    def authorize_interface(self, intf_dir, value: int) -> None:
        # The response used to be discarded, which is the project's recurring
        # bug in miniature: a refusal from the gate looked exactly like
        # success, so deferred_bind would report "interface held unbound" for
        # an interface that was never touched -- a security property claimed
        # but not delivered. Callers already handle OSError (GateError is one).
        resp, _ = self._round_trip(protocol.Request(
            protocol.REQ_AUTHORIZE_INTERFACE, path=str(intf_dir), value=value))
        if not resp.ok:
            raise GateError(
                f"authorize_interface failed: {resp.status}: {resp.detail}")

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

    # See the note below the fd helpers: the gate cannot scope a bus-wide
    # operation, so it does not carry one. deferred_bind reads this flag and
    # declines to start, rather than discovering the problem halfway through
    # with autoprobe already switched off.
    supports_bus_wide = False

    def __init__(self, client: "GateClient"):
        self.client = client

    def admit(self, syspath, instance) -> None:
        self.client.admit(syspath, instance)

    def authorize(self, syspath, value: int) -> None:
        self.client.authorize(syspath, value)

    def authorize_interface(self, intf_dir, value: int) -> None:
        # Was missing entirely: sysfs.set_interface_authorized() routes through
        # the active backend, so under --privsep the deferred-bind path raised
        # AttributeError instead of authorizing an interface.
        self.client.authorize_interface(intf_dir, value)

    def set_default(self, hub, value: int) -> None:
        self.client.set_default(hub, value)

    def open_input(self, node_path) -> int:
        return self.client.open_input(node_path)

    def open_block(self, device_path) -> int:
        return self.client.open_block(device_path)

    # ---- deliberately NOT available under privilege separation ----
    #
    # The gate's entire scoping rule is "act only on a USB device the kernel
    # reports as authorized=0". drivers_autoprobe and drivers_probe are bus-wide:
    # there is no device to scope them to, so the gate has no way to tell a
    # legitimate request from a compromised analyzer switching driver binding
    # off for the whole machine. Rather than invent a weaker rule for the most
    # dangerous operation, the split simply does not carry it.
    #
    # These raise instead of returning quietly, because deferred_bind's
    # supported() check must FAIL when this backend is installed. A no-op would
    # reproduce the exact bug being fixed here: a race-closing mechanism that
    # reports success while doing nothing.

    def set_drivers_autoprobe(self, value: int) -> None:
        raise NotImplementedError(
            "drivers_autoprobe is bus-wide and cannot be scoped to a "
            "quarantined device, so the privileged gate does not offer it")

    def trigger_driver_probe(self, name: str) -> None:
        raise NotImplementedError(
            "drivers_probe is bus-wide and is not offered by the gate")
