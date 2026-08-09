"""
Tests for privilege separation.

The security of the whole split rests on two things being correct: the gate
refuses paths outside its two allowed prefixes, and the privilege drop actually
drops. Both are tested here without needing root or real hardware -- the path
validation is pure logic, and the protocol is pure serialisation.

An end-to-end socketpair test exercises the real message flow, including
passing a file descriptor over SCM_RIGHTS, because that mechanism is subtle
enough to be worth proving rather than assuming.
"""

import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from probolos import gate_server, protocol
from probolos.gate_client import GateClient


class TestProtocol(unittest.TestCase):

    def test_request_round_trips(self):
        req = protocol.Request(protocol.REQ_AUTHORIZE, path="/x", value=1)
        self.assertEqual(protocol.Request.decode(req.encode()).value, 1)

    def test_unknown_request_kind_is_rejected(self):
        with self.assertRaises(ValueError):
            protocol.Request.decode(b'{"kind":"rm -rf"}')

    def test_non_integer_value_is_rejected(self):
        with self.assertRaises(ValueError):
            protocol.Request.decode(b'{"kind":"authorize","value":"1"}')

    def test_oversized_message_is_rejected(self):
        with self.assertRaises(ValueError):
            protocol.Request.decode(b'{"kind":"ping","path":"' +
                                    b"x" * (protocol.MAX_MESSAGE) + b'"}')

    def test_malformed_json_is_rejected(self):
        with self.assertRaises(ValueError):
            protocol.Request.decode(b"not json at all")

    def test_non_object_is_rejected(self):
        with self.assertRaises(ValueError):
            protocol.Request.decode(b'[1,2,3]')

    def test_response_round_trips(self):
        r = protocol.Response(protocol.OK, "fine", has_fd=True)
        back = protocol.Response.decode(r.encode())
        self.assertTrue(back.ok)
        self.assertTrue(back.has_fd)


class TestGatePathValidation(unittest.TestCase):
    """
    The security boundary. The gate must refuse every path outside its two
    allowed trees, however the analyzer dresses it up.
    """

    def test_usb_path_outside_tree_is_refused(self):
        self.assertIsNone(gate_server.GateServer._safe_usb_path("/etc/shadow"))

    def test_usb_path_traversal_is_refused(self):
        """realpath collapses ../ before the prefix check."""
        evil = "/sys/bus/usb/devices/../../../etc/shadow"
        self.assertIsNone(gate_server.GateServer._safe_usb_path(evil))

    def test_input_path_outside_tree_is_refused(self):
        self.assertIsNone(
            gate_server.GateServer._safe_input_path("/etc/passwd"))

    def test_input_path_must_be_an_event_node(self):
        # /dev/input/mice exists on many systems but is not an eventN node.
        self.assertIsNone(
            gate_server.GateServer._safe_input_path("/dev/input/mice"))

    def test_nonexistent_usb_path_is_refused(self):
        self.assertIsNone(
            gate_server.GateServer._safe_usb_path(
                "/sys/bus/usb/devices/does-not-exist-9-9"))

    def test_orphan_devices_path_is_refused(self):
        """
        A device under /sys/devices/ that is NOT linked from the USB bus view
        must be refused: only genuine USB nodes are reachable both ways.
        """
        self.assertIsNone(
            gate_server.GateServer._safe_usb_path(
                "/sys/devices/pci0000:00/some-non-usb-device"))

    def test_both_path_forms_accepted_for_a_real_usb_node(self):
        """
        The 0.6.0 regression: paths arrive both as the bus-view symlink
        (sysfs.list_devices) and as the resolved /sys/devices path (pyudev
        sys_path) for the SAME device. Both must be accepted; a non-USB device
        under /sys/devices with no bus link must not. Uses a synthetic tree so
        it runs without real USB hardware.
        """
        import os
        import tempfile
        from pathlib import Path
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp) / "sys" / "devices" / "usb5" / "5-1"
            real.mkdir(parents=True)
            busdir = Path(tmp) / "sys" / "bus" / "usb" / "devices"
            busdir.mkdir(parents=True)
            (busdir / "5-1").symlink_to(real)
            orphan = Path(tmp) / "sys" / "devices" / "platform" / "evil"
            orphan.mkdir(parents=True)

            with mock.patch.object(gate_server, "USB_LINK_PREFIX",
                                   str(busdir) + "/"), \
                 mock.patch.object(gate_server, "USB_REAL_PREFIX",
                                   str(Path(tmp) / "sys" / "devices") + "/"):
                G = gate_server.GateServer
                # both forms of the real device resolve and are accepted
                self.assertEqual(G._safe_usb_path(str(busdir / "5-1")),
                                 Path(os.path.realpath(real)))
                self.assertEqual(G._safe_usb_path(str(real)),
                                 Path(os.path.realpath(real)))
                # the orphan (no bus link) is refused
                self.assertIsNone(G._safe_usb_path(str(orphan)))


class TestGateRefusesBadRequests(unittest.TestCase):
    """
    Drive the real server over a socketpair and confirm it denies what it
    should, including a path traversal and an out-of-range value.
    """

    def setUp(self):
        self.a, self.b = socket.socketpair(socket.AF_UNIX,
                                           socket.SOCK_SEQPACKET)
        self.server = gate_server.GateServer(self.b, log=lambda *a: None)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.client = GateClient(self.a)

    def tearDown(self):
        self.a.close()
        self.b.close()

    def test_ping_works(self):
        self.assertTrue(self.client.ping())

    def test_authorize_outside_usb_tree_is_denied(self):
        from probolos.gate_client import GateError
        with self.assertRaises(GateError):
            self.client.authorize("/etc/shadow", 1)

    def test_authorize_with_bad_value_errors(self):
        from probolos.gate_client import GateError
        with self.assertRaises(GateError):
            # value 7 is neither 0 nor 1
            self.client.authorize("/sys/bus/usb/devices/usb1", 7)

    def test_open_input_outside_tree_is_denied(self):
        from probolos.gate_client import GateError
        with self.assertRaises(GateError):
            self.client.open_input("/etc/passwd")


class TestFdPassing(unittest.TestCase):
    """
    Prove SCM_RIGHTS actually moves a working fd across the socket, using a
    temp file to stand in for an input node (the mechanism is identical; only
    gate_server's path check distinguishes them, and that is tested above).
    """

    def test_a_real_fd_crosses_the_socket(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"hello over the wire")
            name = tf.name
        try:
            # Server side: open the file and send its fd back.
            def serve_once():
                data = b.recv(protocol.MAX_MESSAGE)
                protocol.Request.decode(data)  # validate shape
                fd = os.open(name, os.O_RDONLY)
                import array
                b.sendmsg([protocol.Response(protocol.OK, has_fd=True).encode()],
                          [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                            array.array("i", [fd]))])
                os.close(fd)

            t = threading.Thread(target=serve_once, daemon=True)
            t.start()

            client = GateClient(a)
            resp, fd = client._round_trip(
                protocol.Request(protocol.REQ_OPEN_INPUT, path="/x"),
                expect_fd=True)
            self.assertTrue(resp.ok)
            self.assertIsNotNone(fd)
            # The received fd must be independently usable.
            self.assertEqual(os.read(fd, 5), b"hello")
            os.close(fd)
        finally:
            a.close()
            b.close()
            os.unlink(name)


class TestPrivilegeDrop(unittest.TestCase):
    """
    The drop logic is guarded so it cannot be tested destructively, but its
    no-op-when-not-root path can be, and the ordering assertions in the source
    are what a reviewer checks. Here we confirm it does nothing when already
    unprivileged rather than raising.
    """

    def test_drop_is_a_noop_when_not_root(self):
        from probolos import privsep
        # We are not root in CI; this must return quietly, not blow up.
        if os.getuid() != 0:
            privsep.drop_privileges(12345, 12345)  # should not raise

    def test_resolve_user_rejects_unknown(self):
        from probolos import privsep
        with self.assertRaises(privsep.PrivsepError):
            privsep.resolve_user("no-such-user-probolos-xyz")

    def test_resolve_nobody_exists(self):
        from probolos import privsep
        uid, gid = privsep.resolve_user("nobody")
        self.assertIsInstance(uid, int)


if __name__ == "__main__":
    unittest.main(verbosity=2)
