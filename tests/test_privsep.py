"""
The privilege split: the root gate's scope checks, its wire protocol, the
client that talks to it, and dropping privilege in the analyzer.

Covers probolos.privsep, probolos.gate_server, probolos.gate_client and
probolos.protocol.
"""

from __future__ import annotations

import os
import pty
import select
import signal
import socket
import shutil
import tempfile
import termios
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from probolos import (
    agentlink,
    gate_client,
    gate_server,
    ledger,
    privsep,
    protocol,
    sysfs,
    textsafe,
    trust,
)
from probolos.gate_client import GateClient
from tests._support import descriptor_blob


@unittest.skipUnless(os.geteuid() == 0, "privsep.start() needs root")
class AnalyzerHasNoControllingTerminal(unittest.TestCase):
    """The analyzer could TIOCSTI into the terminal Probolos was started from."""

    GATE_UP = b"<gate-up>"

    def _run(self, analyzer_body, while_running=None) -> str:
        """
        privsep.start() as a job started from a shell on a terminal.

        The pty child plays the shell: it leads the terminal's session and
        runs the gate in a foreground process group of its own, as a shell
        does. Without that layer the gate's group is orphaned, and the kernel
        discards Ctrl-Z for orphaned groups, which would hide the difference
        the job-control test is about. The "shell" reports on the pipe if the
        gate is ever stopped, and resumes it.
        """
        try:
            privsep.resolve_user("nobody")
        except privsep.PrivsepError as exc:
            self.skipTest(str(exc))
        read_end, write_end = os.pipe()
        pid, master = pty.fork()
        if pid == 0:
            os.close(read_end)
            try:
                gate = os.fork()
                if gate == 0:
                    os.setpgid(0, 0)
                    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
                    os.tcsetpgrp(0, os.getpid())
                    signal.signal(signal.SIGTTOU, signal.SIG_DFL)

                    def analyzer_main(_gate):
                        analyzer_body(write_end)
                        return 0
                    try:
                        # The gate's log line is written once its signal
                        # handlers are in place: keys are pressed after it.
                        privsep.start(analyzer_main, log=lambda *_a: os.write(
                            write_end, self.GATE_UP))
                    finally:
                        os._exit(0)
                while True:
                    _pid, status = os.waitpid(gate, os.WUNTRACED)
                    if not os.WIFSTOPPED(status):
                        break
                    os.write(write_end, b"gate-stopped ")
                    os.killpg(gate, signal.SIGCONT)
            finally:
                os._exit(0)
        os.close(write_end)
        report = b""
        finished = False
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([read_end, master], [], [], 0.2)
                if master in ready:
                    try:
                        os.read(master, 4096)
                    except OSError:
                        pass
                if read_end in ready:
                    chunk = os.read(read_end, 4096)
                    if not chunk:
                        finished = True
                        break
                    report += chunk
                    if (while_running is not None and b"ready" in report
                            and self.GATE_UP in report):
                        while_running(master)
                        while_running = None
        finally:
            os.close(read_end)
            if not finished:
                os.kill(pid, signal.SIGKILL)   # fail, never hang the suite
            os.waitpid(pid, 0)
            os.close(master)
        return report.replace(self.GATE_UP, b"").decode()

    def test_the_analyzer_leads_its_own_session_and_cannot_inject(self):
        import fcntl

        def body(out):
            own = os.getsid(0) == os.getpid()
            try:
                fcntl.ioctl(0, termios.TIOCSTI, b"X")
                injected = "injected"
            except OSError:
                injected = "refused"
            os.write(out, f"session={own} tiocsti={injected}".encode())

        self.assertEqual(self._run(body), "session=True tiocsti=refused")

    @staticmethod
    def _wait_for_ctrl_c(out):
        os.write(out, b"ready ")
        try:
            time.sleep(10)
            os.write(out, b"no-sigint")
        except KeyboardInterrupt:
            os.write(out, b"sigint")

    def test_ctrl_c_at_the_terminal_still_reaches_the_analyzer(self):
        """GUARD: off the terminal's session, Ctrl-C is forwarded by the gate."""
        self.assertEqual(
            self._run(self._wait_for_ctrl_c,
                      while_running=lambda m: os.write(m, b"\x03")),
            "ready sigint")

    def test_ctrl_z_does_not_suspend_the_gate(self):
        """GUARD: a suspended gate would hand the shell a terminal the
        analyzer, outside job control now, is still reading."""
        def press_ctrl_z_then_ctrl_c(master):
            os.write(master, b"\x1a")
            time.sleep(0.3)
            os.write(master, b"\x03")

        self.assertEqual(
            self._run(self._wait_for_ctrl_c, press_ctrl_z_then_ctrl_c),
            "ready sigint")


class GateScope(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

        self.devices = self.root / "sys/devices"
        self.usb_blocked = self.devices / "pci0/usb1/1-1"
        self.usb_blocked.mkdir(parents=True)
        (self.usb_blocked / "authorized").write_text("0\n")
        self.usb_authed = self.devices / "pci0/usb1/1-2"
        self.usb_authed.mkdir(parents=True)
        (self.usb_authed / "authorized").write_text("1\n")
        self.ps2 = self.devices / "platform/i8042/serio0"
        self.ps2.mkdir(parents=True)

        self.busview = self.root / "sys/bus/usb/devices"
        self.busview.mkdir(parents=True)
        os.symlink(self.usb_blocked, self.busview / "1-1")
        os.symlink(self.usb_authed, self.busview / "1-2")

        self.cls = self.root / "sys/class"
        self._make_class_node("input", "event5", self.usb_blocked)
        self._make_class_node("input", "event9", self.usb_authed)
        self._make_class_node("input", "event0", self.ps2)
        self._make_class_node("block", "sdz", self.usb_blocked)

        self.dev = self.root / "dev"
        (self.dev / "input").mkdir(parents=True)
        for n in ("event5", "event9", "event0"):
            (self.dev / "input" / n).write_bytes(b"")
        (self.dev / "sdz").write_bytes(b"")

        self._patchers = [
            mock.patch.object(gate_server, "USB_REAL_PREFIX",
                              str(self.devices) + "/"),
            mock.patch.object(gate_server, "USB_LINK_PREFIX",
                              str(self.busview) + "/"),
            mock.patch.object(gate_server, "SYS_CLASS_PREFIX",
                              str(self.cls) + "/"),
        ]
        for p in self._patchers:
            p.start()
            self.addCleanup(p.stop)

    def _make_class_node(self, cls_dir, node, real_dev):
        d = self.root / "sys/class" / cls_dir / node
        d.mkdir(parents=True)
        os.symlink(real_dev, d / "device")

    # ---- _usb_device_is_blocked ----

    def test_blocked_device_reads_as_blocked(self):
        self.assertTrue(
            gate_server.GateServer._usb_device_is_blocked(self.usb_blocked))

    def test_authorized_device_reads_as_not_blocked(self):
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.usb_authed))

    def test_missing_authorized_fails_closed(self):
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.ps2))

    # ---- _blocked_usb_parent_of ----

    def test_event_under_quarantined_device_is_in_scope(self):
        node = self.dev / "input" / "event5"
        self.assertEqual(
            gate_server.GateServer._blocked_usb_parent_of(node),
            self.usb_blocked)

    def test_event_under_authorized_device_is_out_of_scope(self):
        node = self.dev / "input" / "event9"
        self.assertIsNone(
            gate_server.GateServer._blocked_usb_parent_of(node))

    def test_builtin_ps2_keyboard_is_never_in_scope(self):
        """The keylogger vector: event0 has no USB parent, so it is refused."""
        node = self.dev / "input" / "event0"
        self.assertIsNone(
            gate_server.GateServer._blocked_usb_parent_of(node))

    def test_usb_disk_under_quarantine_is_in_scope(self):
        node = self.dev / "sdz"
        self.assertEqual(
            gate_server.GateServer._blocked_usb_parent_of(node),
            self.usb_blocked)


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


# ---------------------------------------------------------------------------
# 5. The privileged gate: without this the watcher is dead under --privsep
# ---------------------------------------------------------------------------

class GateMediaScope(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.devices = root / "sys/devices"
        self.busview = root / "sys/bus/usb/devices"
        self.busview.mkdir(parents=True)
        self.cls = root / "sys/class"
        self.dev = root / "dev"
        self.dev.mkdir()

        self.reader = self._usb("1-2", authorized="1", classes=["08"])
        self.combo = self._usb("1-3", authorized="1", classes=["08", "03"])
        self.later = self._usb("1-4", authorized="0", classes=["08"])
        for node, owner in (("sdz", self.reader), ("sdy", self.combo),
                            ("sdx", self.later)):
            d = self.cls / "block" / node
            d.mkdir(parents=True)
            os.symlink(owner, d / "device")
            (self.dev / node).write_bytes(b"")

        for attr, value in (("USB_REAL_PREFIX", str(self.devices) + "/"),
                            ("USB_LINK_PREFIX", str(self.busview) + "/"),
                            ("SYS_CLASS_PREFIX", str(self.cls) + "/")):
            p = mock.patch.object(gate_server, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def _usb(self, name, authorized, classes):
        path = self.devices / "pci0/usb1" / name
        path.mkdir(parents=True)
        (path / "authorized").write_text(authorized + "\n")
        for i, cls in enumerate(classes):
            intf = path / f"{name}:1.{i}"
            intf.mkdir()
            (intf / "bInterfaceClass").write_text(cls + "\n")
        os.symlink(path, self.busview / name)
        return path

    def gate(self, watch_media=True):
        return gate_server.GateServer(sock=None, log=lambda *_a: None,
                                      watch_media=watch_media)

    def test_off_by_default(self):
        gate = self.gate(watch_media=False)
        self.assertIsNone(gate._media_scope_parent_of(self.dev / "sdz"))
        self.assertIsNone(gate._open_scope_parent_of(self.dev / "sdz"))

    def test_a_reader_present_at_startup_is_in_scope(self):
        gate = self.gate()
        self.assertEqual(gate._media_scope_parent_of(self.dev / "sdz"),
                         self.reader)

    def test_a_composite_is_never_in_scope(self):
        gate = self.gate()
        self.assertIsNone(gate._media_scope_parent_of(self.dev / "sdy"))

    def test_a_reader_admitted_through_the_gate_enters_scope(self):
        gate = self.gate()
        self.assertNotIn(str(self.later), gate._media_hosts)
        st = self.later.stat()
        resp = gate._do_admit(protocol.Request(
            protocol.REQ_ADMIT, path=str(self.later), value=1,
            instance=(st.st_dev, st.st_ino)))
        self.assertTrue(resp.ok, resp.detail)
        self.assertEqual(gate._media_scope_parent_of(self.dev / "sdx"),
                         self.later)

    def test_a_recycled_port_leaves_scope(self):
        gate = self.gate()
        gate._media_hosts[str(self.reader)] = (0, 0)
        self.assertIsNone(gate._media_scope_parent_of(self.dev / "sdz"))

    def test_a_watched_reader_may_be_switched_off_never_on(self):
        gate = self.gate()
        on = gate._do_authorize(protocol.Request(
            protocol.REQ_AUTHORIZE, path=str(self.reader), value=1))
        self.assertFalse(on.ok)
        off = gate._do_authorize(protocol.Request(
            protocol.REQ_AUTHORIZE, path=str(self.reader), value=0))
        self.assertTrue(off.ok, off.detail)
        self.assertEqual((self.reader / "authorized").read_text(), "0")
        self.assertNotIn(str(self.reader), gate._media_hosts)

    def test_an_unwatched_live_device_still_cannot_be_switched_off(self):
        gate = self.gate()
        resp = gate._do_authorize(protocol.Request(
            protocol.REQ_AUTHORIZE, path=str(self.combo), value=0))
        self.assertEqual(resp.status, protocol.DENIED)

    def test_open_block_consults_the_media_scope(self):
        gate = self.gate()
        node = self.dev / "sdz"
        # The node here is a regular file, so the descriptor-level whole-disk
        # check is stubbed along with the path-level one: this test is about
        # scope, and the descriptor check has its own tests in test_sysfs.
        with mock.patch.object(gate_server.GateServer, "_check_block_path",
                               staticmethod(lambda _p: (node, ""))), \
                mock.patch.object(gate_server.GateServer, "_whole_disk_reason",
                                  staticmethod(lambda _st, _name: "")):
            resp, fd = gate._do_open_block(protocol.Request(
                protocol.REQ_OPEN_BLOCK, path=str(node)))
        self.assertTrue(resp.ok, resp.detail)
        os.close(fd)

    def test_run_gate_forwards_the_flag(self):
        seen = {}

        class Recorder:
            def __init__(self, sock, log, watch_media, trust_path=None):
                seen["watch_media"] = watch_media
                seen["trust_path"] = trust_path

            def serve_forever(self):
                pass

        with mock.patch.object(gate_server, "GateServer", Recorder):
            gate_server.run_gate(None, watch_media=True,
                                 trust_path="/var/lib/probolos/trusted.json")
        self.assertTrue(seen["watch_media"])
        self.assertEqual(seen["trust_path"], "/var/lib/probolos/trusted.json")


# ---------------------------------------------------------------------------
# 4. The gate's own scope check
# ---------------------------------------------------------------------------

class GateScopeCheckIsNotRedirectable(unittest.TestCase):
    """
    _usb_device_is_blocked answers "is this device under quarantine?", and
    that answer is the entire scoping rule for open_input, open_block and
    interface authorization. It read `authorized` by name, so a symlink there
    aimed the gate's central check at a file of the analyzer's choosing -- and
    a "0" read out of that file turns every scope check in the class into a
    yes. The WRITES were pinned and the read that authorizes them was not,
    which is the wrong half to leave open.
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.devdir = self.root / "1-1"
        self.devdir.mkdir()

    def test_a_symlinked_authorized_does_not_read_as_blocked(self):
        decoy = self.root / "decoy"
        decoy.write_text("0")
        (self.devdir / "authorized").symlink_to(decoy)
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.devdir),
            "a symlinked `authorized` must not be able to claim quarantine")

    def test_a_real_blocked_device_still_reads_as_blocked(self):
        (self.devdir / "authorized").write_text("0")
        self.assertTrue(
            gate_server.GateServer._usb_device_is_blocked(self.devdir))

    def test_a_real_live_device_still_reads_as_live(self):
        (self.devdir / "authorized").write_text("1")
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.devdir))

    def test_a_missing_attribute_fails_closed(self):
        self.assertFalse(
            gate_server.GateServer._usb_device_is_blocked(self.devdir))

    def test_interface_parent_must_pass_safe_usb_path(self):
        """
        `intf.parent` was plain path arithmetic on an analyzer-supplied
        string: the gate trusting the analyzer to describe the very
        relationship the gate exists to verify. A parent that is not a
        genuine, bus-reachable USB device is now refused outright.
        """
        server = gate_server.GateServer(mock.Mock())
        intf = self.root / "1-1:1.0"
        intf.mkdir()
        (intf / "authorized").write_text("0")

        with mock.patch.object(server, "_safe_usb_path",
                               side_effect=lambda p: (
                                   intf if str(p) == str(intf) else None)):
            resp = server._do_authorize_interface(protocol.Request(
                protocol.REQ_AUTHORIZE_INTERFACE, str(intf), 1))

        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("parent", resp.detail)


class InterfacesAreRestored(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

        self.devices = self.root / "sys/devices"
        self.device = self.devices / "pci0/usb1/1-1"
        self.device.mkdir(parents=True)
        (self.device / "authorized").write_text("0\n")
        self.iface = self.device / "1-1:1.0"
        self.iface.mkdir()
        (self.iface / "authorized").write_text("1\n")

        self.busview = self.root / "sys/bus/usb/devices"
        self.busview.mkdir(parents=True)
        os.symlink(self.device, self.busview / "1-1")
        os.symlink(self.iface, self.busview / "1-1:1.0")

        for name, value in (("USB_REAL_PREFIX", str(self.devices) + "/"),
                            ("USB_LINK_PREFIX", str(self.busview) + "/")):
            patcher = mock.patch.object(gate_server, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.gate = gate_server.GateServer(sock=None, log=lambda *_a: None)

    def _unbind(self):
        return self.gate._do_authorize_interface(protocol.Request(
            protocol.REQ_AUTHORIZE_INTERFACE, str(self.iface), 0))

    def test_an_unbound_interface_is_put_back_on_restore(self):
        self.assertTrue(self._unbind().ok)
        self.assertEqual((self.iface / "authorized").read_text(), "0")

        self.gate.restore()
        self.assertEqual((self.iface / "authorized").read_text(), "1",
                         "the gate left an interface deauthorized after the "
                         "analyzer went away; nothing else will ever put it "
                         "back")

    def test_an_interface_the_analyzer_rebound_is_not_touched_again(self):
        self.assertTrue(self._unbind().ok)
        self.assertTrue(self.gate._do_authorize_interface(protocol.Request(
            protocol.REQ_AUTHORIZE_INTERFACE, str(self.iface), 1)).ok)
        self.assertEqual(self.gate._interfaces_off, {})

    def test_a_recycled_port_is_not_re_authorized(self):
        """
        The same instance discipline the device paths already get. A port
        recycled since the write means this directory belongs to different
        hardware, and authorizing an interface of a device nobody inspected is
        what _do_authorize_interface refuses to do on the request path.
        """
        self.assertTrue(self._unbind().ok)
        replacement = self.device / "replacement"
        replacement.mkdir()
        (replacement / "authorized").write_text("0\n")
        self.iface.rename(self.device / "gone")
        replacement.rename(self.iface)

        self.gate.restore()
        self.assertEqual((self.iface / "authorized").read_text().strip(), "0")

    def test_restore_reports_a_failure_instead_of_raising(self):
        self.assertTrue(self._unbind().ok)
        (self.iface / "authorized").unlink()
        messages = []
        self.gate.log = messages.append
        self.gate.restore()          # must not raise
        self.assertTrue(any("re-authorize" in m for m in messages), messages)


class SupplementaryGroupsMustBeGone(unittest.TestCase):

    def _drop_with_groups(self, groups):
        """Run drop_privileges as though it were root, with a chosen result."""
        with mock.patch.object(os, "getuid", return_value=0), \
             mock.patch.object(os, "setgroups"), \
             mock.patch.object(os, "setgid"), \
             mock.patch.object(os, "setuid",
                               side_effect=[None, PermissionError()]), \
             mock.patch.object(os, "geteuid", return_value=65534), \
             mock.patch.object(os, "getgid", return_value=65534), \
             mock.patch.object(os, "getegid", return_value=65534), \
             mock.patch.object(os, "getgroups", return_value=groups):
            # getuid must read 0 on entry and 65534 after the drop.
            os.getuid.side_effect = [0, 65534]
            privsep.drop_privileges(65534, 65534)

    def test_a_surviving_group_stops_the_drop(self):
        with self.assertRaises(privsep.PrivsepError) as caught:
            self._drop_with_groups([65534, 27])     # 27 == sudo on Debian
        self.assertIn("supplementary groups", str(caught.exception))

    def test_the_primary_gid_alone_is_accepted(self):
        self._drop_with_groups([65534])             # must not raise

    def test_no_groups_at_all_is_accepted(self):
        self._drop_with_groups([])                  # must not raise


class DeadAnalyzerDoesNotKillTheGate(unittest.TestCase):
    """
    The analyzer exits between sending a request and reading the reply.

    sendmsg() then returns EPIPE. Nothing caught it: the exception left
    _serve_requests, left run_gate, and left privsep.start() -- which never
    reached its os.waitpid(), so the root process died with a traceback and
    the analyzer child was orphaned. Ctrl-C is enough to produce this.
    """

    def test_epipe_ends_the_loop_cleanly(self):
        from probolos import gate_server, protocol

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        gate = gate_server.GateServer(a, log=lambda *x: None)
        b.sendall(protocol.Request(protocol.REQ_PING).encode())
        b.close()
        gate.serve_forever()      # must simply return
        a.close()

    def test_a_handler_that_raises_does_not_end_the_gate(self):
        """
        Every handler is written to return a Response rather than raise, so
        reaching this path is itself a bug -- which is exactly why the loop
        must survive it instead of trusting it cannot happen.
        """
        from probolos import gate_server, protocol

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        gate = gate_server.GateServer(a, log=lambda *x: None)

        def boom(_req):
            raise RuntimeError("bug in a handler")

        gate._do_authorize = boom
        b.sendall(protocol.Request(protocol.REQ_AUTHORIZE,
                                   path="/sys/bus/usb/devices/1-1",
                                   value=1).encode())
        b.settimeout(2.0)
        thread = threading.Thread(target=gate.serve_forever, daemon=True)
        thread.start()
        raw = b.recv(protocol.MAX_MESSAGE)
        resp = protocol.Response.decode(raw)
        self.assertEqual(resp.status, protocol.ERROR)
        self.assertIn("internal gate error", resp.detail)
        b.close()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        a.close()

    def test_a_denial_stays_inside_the_clients_message_limit(self):
        """
        The denial echoes a path the analyzer chose. A reply its own decoder
        refuses as oversized tells it nothing at all.
        """
        from probolos import gate_server, protocol

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        gate = gate_server.GateServer(a, log=lambda *x: None)
        long_path = "/sys/bus/usb/devices/" + "A" * 7900
        b.sendall(protocol.Request(protocol.REQ_AUTHORIZE_INTERFACE,
                                   path=long_path, value=1).encode())
        b.settimeout(2.0)
        thread = threading.Thread(target=gate.serve_forever, daemon=True)
        thread.start()
        raw = b.recv(protocol.MAX_MESSAGE)
        protocol.Response.decode(raw)      # must not raise "message too large"
        self.assertLessEqual(len(raw), protocol.MAX_MESSAGE)
        b.close()
        thread.join(timeout=3)
        a.close()


class SysfsWritesTruncate(unittest.TestCase):
    """
    O_WRONLY alone overwrites from byte zero and leaves whatever was longer.

    Harmless against a real sysfs attribute, which the kernel handles as a
    store() call -- and wrong everywhere else, including every test fixture
    that stands in for one. Writing "0" over "not-a-number" must not leave
    "0ot-a-number" behind for the next read to parse.
    """

    def test_authorized_default_is_truncated_on_write(self):
        from probolos import gate_server, protocol

        with tempfile.TemporaryDirectory() as tmp:
            hub = Path(tmp) / "usb1"
            hub.mkdir()
            attr = hub / "authorized_default"
            attr.write_text("this is much longer than one digit")

            gate = gate_server.GateServer.__new__(gate_server.GateServer)
            gate._authorized_here = set()
            gate._closed_defaults = {}
            gate._open_leases = {}
            gate._instances = {}
            gate._safe_usb_path = staticmethod(lambda p: hub)
            gate.log = lambda *a: None

            resp = gate_server.GateServer._do_set_default(
                gate, protocol.Request(protocol.REQ_SET_DEFAULT, str(hub), 0))
            self.assertTrue(resp.ok, resp.detail)
            self.assertEqual(attr.read_text(), "0")

    def test_the_direct_backend_truncates_authorized_too(self):
        import inspect

        from probolos import sysfs

        # admit() and an instance-bound activation share the one write.
        self.assertIn("_write_to_instance",
                      inspect.getsource(sysfs._DirectBackend.admit))
        self.assertIn("O_TRUNC",
                      inspect.getsource(sysfs._DirectBackend._write_to_instance))


class AnalyzerChildAlwaysEndsInAnExitStatus(unittest.TestCase):
    """
    The forked analyzer must leave through os._exit(). SystemExit is not an
    Exception, so a deliberate exit inside serve() -- a leftover panic file, a
    missing pyudev, the gate's own signal handler -- escaped the child's
    handler and unwound through the parent's stack in the child process.
    """

    def _rc(self, analyzer_main):
        import contextlib
        import io

        from probolos import privsep
        with contextlib.redirect_stderr(io.StringIO()):
            return privsep._run_analyzer(analyzer_main, object())

    def _raises(self, exc):
        def analyzer_main(_client):
            raise exc
        return analyzer_main

    def test_system_exit_becomes_a_status(self):
        self.assertEqual(self._rc(self._raises(SystemExit(0))), 0)
        self.assertEqual(self._rc(self._raises(SystemExit(None))), 0)
        self.assertEqual(self._rc(self._raises(SystemExit(3))), 3)
        self.assertEqual(self._rc(self._raises(SystemExit("message"))), 1)

    def test_the_other_endings_are_unchanged(self):
        self.assertEqual(self._rc(lambda _c: 0), 0)
        self.assertEqual(self._rc(lambda _c: None), 0)
        self.assertEqual(self._rc(lambda _c: 4), 4)
        self.assertEqual(self._rc(self._raises(KeyboardInterrupt())), 0)
        self.assertEqual(self._rc(self._raises(RuntimeError("boom"))), 1)


class DirectorySeparation(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.root = Path(self._d.name)

    def test_refuses_to_hand_over_a_directory_holding_trust(self):
        """The core of the fix: that directory must never be chowned away."""
        (self.root / "trusted.json").write_text("{}")
        ledger = self.root / "ledger.json"
        logged = []
        privsep.prepare_state_dir(ledger, uid=65534, gid=65534,
                                  log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged),
                        "handing over a trust-store directory was not refused")

    def test_a_clean_subdirectory_is_still_handed_over(self):
        """The refusals must not break the legitimate ledger path."""
        state = self.root / "state"
        state.mkdir()
        ledger = state / "ledger.json"
        logged = []
        # The tempdir is outside STATE_ROOTS, which is itself a refusal reason
        # (see test_refuses_a_directory_outside_the_state_roots). Point the
        # allowlist at it so this test exercises only the trust-store rule.
        with mock.patch.object(privsep, "STATE_ROOTS", (str(self.root),)):
            # chown will fail for non-root; what matters is that it was
            # ATTEMPTED, i.e. we got past both refusals.
            privsep.prepare_state_dir(ledger, uid=os.getuid(), gid=os.getgid(),
                                      log=logged.append)
        self.assertFalse(any("REFUSING" in line for line in logged))

    def test_refuses_a_directory_outside_the_state_roots(self):
        """
        A typo must not cost the machine: `--ledger /etc/x.json` would chown
        /etc to an unprivileged account at mode 0700, taking sudo, ssh and PAM
        with it on a running system.
        """
        logged = []
        privsep.prepare_state_dir("/etc/probolos-typo.json", uid=65534,
                                  gid=65534, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))

    def test_traversal_out_of_a_state_root_is_refused(self):
        """realpath runs first, so ../ cannot smuggle a path back out."""
        logged = []
        privsep.prepare_state_dir("/var/lib/probolos/../../../etc/x.json",
                                  uid=65534, gid=65534, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))

    def test_a_sibling_sharing_the_prefix_is_refused(self):
        """/var/lib/probolos-evil must not match /var/lib/probolos."""
        logged = []
        privsep.prepare_state_dir("/var/lib/probolos-evil/x.json", uid=65534,
                                  gid=65534, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))

    def test_trust_is_made_readable_not_writable(self):
        target = self.root / "trusted.json"
        target.write_text("{}")
        os.chmod(target, 0o600)
        privsep.prepare_trust_readable(target, log=lambda *_: None)
        mode = target.stat().st_mode & 0o777
        self.assertTrue(mode & 0o044, "analyzer cannot read the trust store")
        self.assertFalse(mode & 0o022, "trust store became group/other writable")


class GateBackendCompleteness(unittest.TestCase):

    def test_backend_implements_every_method_sysfs_routes(self):
        """
        The real defect was a missing method, so pin the whole surface rather
        than that one name: every method _DirectBackend exposes must also exist
        on GateBackend, or some call works as root and crashes under --privsep.
        """
        direct = {n for n in dir(sysfs._DirectBackend)
                  if not n.startswith("_")}
        gated = {n for n in dir(gate_client.GateBackend)
                 if not n.startswith("_")}
        missing = direct - gated
        self.assertEqual(missing, set(),
                         f"GateBackend is missing: {sorted(missing)}")

    def test_authorize_interface_is_routed_to_the_gate(self):
        client = mock.Mock()
        backend = gate_client.GateBackend(client)
        backend.authorize_interface("/sys/bus/usb/devices/1-1:1.0", 1)
        client.authorize_interface.assert_called_once()

    def test_protocol_accepts_the_new_request_kind(self):
        req = protocol.Request(protocol.REQ_AUTHORIZE_INTERFACE,
                               path="/sys/bus/usb/devices/1-1:1.0", value=1)
        decoded = protocol.Request.decode(req.encode())
        self.assertEqual(decoded.kind, protocol.REQ_AUTHORIZE_INTERFACE)
        self.assertEqual(decoded.value, 1)


# ---------------------------------------------------------------------------
# 1. Gate scope: open_input / open_block were unsatisfiable
# ---------------------------------------------------------------------------

class GateOpenScope(unittest.TestCase):
    """
    A device held at authorized=0 is never configured, so it has NO /dev nodes.
    The node only exists once the device is authorized -- which is what
    quarantine and the storage scan do immediately before asking to open it.
    Requiring authorized=0 at open time therefore refused every legitimate
    request, and stages 3 and 4 silently did nothing under --privsep.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

        self.devices = self.root / "sys/devices"
        self.usb = self.devices / "pci0/usb1/1-1"
        self.usb.mkdir(parents=True)
        (self.usb / "authorized").write_text("0\n")

        self.other = self.devices / "pci0/usb1/1-2"       # in use, not ours
        self.other.mkdir(parents=True)
        (self.other / "authorized").write_text("1\n")

        self.ps2 = self.devices / "platform/i8042/serio0"  # built-in keyboard
        self.ps2.mkdir(parents=True)

        self.busview = self.root / "sys/bus/usb/devices"
        self.busview.mkdir(parents=True)
        os.symlink(self.usb, self.busview / "1-1")
        os.symlink(self.other, self.busview / "1-2")

        self.cls = self.root / "sys/class"
        for cls_dir, node, real in (("input", "event5", self.usb),
                                    ("input", "event9", self.other),
                                    ("input", "event0", self.ps2),
                                    ("block", "sdz", self.usb)):
            d = self.cls / cls_dir / node
            d.mkdir(parents=True)
            os.symlink(real, d / "device")

        self.dev = self.root / "dev"
        (self.dev / "input").mkdir(parents=True)
        for n in ("event5", "event9", "event0"):
            (self.dev / "input" / n).write_bytes(b"")
        (self.dev / "sdz").write_bytes(b"")

        for attr, value in (("USB_REAL_PREFIX", str(self.devices) + "/"),
                            ("USB_LINK_PREFIX", str(self.busview) + "/"),
                            ("SYS_CLASS_PREFIX", str(self.cls) + "/")):
            p = mock.patch.object(gate_server, attr, value)
            p.start()
            self.addCleanup(p.stop)

        self.gate = gate_server.GateServer(sock=None, log=lambda *_a: None)

    def _authorize(self, path, value):
        return self.gate._do_authorize(
            protocol.Request(protocol.REQ_AUTHORIZE, path=str(path),
                             value=value))

    # -- the regression itself ------------------------------------------

    def test_input_node_is_openable_after_the_gate_authorized_the_device(self):
        self.assertTrue(self._authorize(self.usb, 1).ok)
        node = self.dev / "input" / "event5"
        self.assertEqual(self.gate._open_scope_parent_of(node), self.usb)

    def test_block_node_is_openable_after_the_gate_authorized_the_device(self):
        self.assertTrue(self._authorize(self.usb, 1).ok)
        self.assertEqual(self.gate._open_scope_parent_of(self.dev / "sdz"),
                         self.usb)

    # -- and the guarantees that must survive the widening ---------------

    def test_builtin_ps2_keyboard_is_still_never_in_scope(self):
        self.assertTrue(self._authorize(self.usb, 1).ok)
        self.assertIsNone(
            self.gate._open_scope_parent_of(self.dev / "input" / "event0"))

    def test_device_the_gate_never_authorized_is_still_refused(self):
        """event9 belongs to a device that was already live. Not ours to read."""
        self.assertIsNone(
            self.gate._open_scope_parent_of(self.dev / "input" / "event9"))

    def test_scope_ends_when_the_device_is_put_back_to_blocked(self):
        self.assertTrue(self._authorize(self.usb, 1).ok)
        (self.usb / "authorized").write_text("1\n")   # kernel state after the scan
        node = self.dev / "input" / "event5"
        self.assertIsNotNone(self.gate._open_scope_parent_of(node))

        self.assertTrue(self._authorize(self.usb, 0).ok)
        (self.usb / "authorized").write_text("0\n")
        self.gate._authorized_here.discard(str(self.usb))
        self.assertIsNotNone(self.gate._open_scope_parent_of(node),
                             "a blocked device is in scope on its own merits")

    def test_lease_expires_so_an_admitted_device_stops_being_readable(self):
        """
        After the user approves, the device stays authorized. Without an expiry
        the analyzer could read the keyboard it had just been admitted.
        """
        self.assertTrue(self._authorize(self.usb, 1).ok)
        (self.usb / "authorized").write_text("1\n")
        node = self.dev / "input" / "event5"
        self.assertIsNotNone(self.gate._open_scope_parent_of(node))

        self.gate._open_leases[str(self.usb)] = 0.0      # force expiry
        self.assertIsNone(self.gate._open_scope_parent_of(node))


class FilesystemPreparation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.victim = self.root / "unrelated"
        self.victim.write_text("private")
        self.victim.chmod(0o400)

    def test_ledger_symlink_does_not_chmod_or_chown_its_target(self):
        (self.state / "ledger.json").symlink_to(self.victim)
        before = self.victim.stat()
        with mock.patch.object(privsep, "STATE_ROOTS", (str(self.state),)):
            privsep.prepare_state_dir(self.state / "ledger.json", os.getuid(),
                                      os.getgid(), log=lambda *_: None)
        after = self.victim.stat()
        self.assertEqual((after.st_uid, after.st_mode), (before.st_uid, before.st_mode))

    def test_allowlisted_root_cannot_be_redefined_by_a_symlink(self):
        alias = self.root / "alias"
        alias.symlink_to(self.state, target_is_directory=True)
        before = self.state.stat().st_mode
        with mock.patch.object(privsep, "STATE_ROOTS", (str(alias),)):
            privsep.prepare_state_dir(alias / "ledger.json", os.getuid(),
                                      os.getgid(), log=lambda *_: None)
        self.assertEqual(self.state.stat().st_mode, before)

    def test_trust_symlink_does_not_make_an_unrelated_file_readable(self):
        target = self.root / "trusted.json"
        target.symlink_to(self.victim)
        privsep.prepare_trust_readable(target, log=lambda *_: None)
        self.assertEqual(self.victim.stat().st_mode & 0o777, 0o400)

    def test_trust_hardlink_is_refused(self):
        target = self.root / "trusted.json"
        os.link(self.victim, target)
        privsep.prepare_trust_readable(target, log=lambda *_: None)
        self.assertEqual(self.victim.stat().st_mode & 0o777, 0o400)

    def test_agent_directory_cannot_chown_arbitrary_parents(self):
        before = self.state.stat().st_mode
        with self.assertRaises(OSError):
            agentlink.prepare_socket_dir(self.state / "agent.sock", os.getuid(), os.getgid())
        self.assertEqual(self.state.stat().st_mode, before)

    def test_audit_log_symlink_cannot_append_to_another_file(self):
        from probolos.securefs import append_json_line
        log = self.state / "audit.jsonl"
        log.symlink_to(self.victim)
        with self.assertRaises(OSError):
            append_json_line(log, {"authorized": True})
        self.assertEqual(self.victim.read_text(), "private")

    def test_atomic_save_refuses_symlink_ancestor(self):
        from probolos import atomicio
        alias = self.root / "alias"
        alias.symlink_to(self.state, target_is_directory=True)
        target = self.state / "ledger.json"
        target.write_text("unchanged")
        with self.assertRaises(OSError):
            atomicio.write_json_atomic(alias / "ledger.json", {"new": True})
        self.assertEqual(target.read_text(), "unchanged")

    def test_fifo_ledger_is_rejected_without_waiting_for_a_writer(self):
        path = self.state / "ledger.json"
        os.mkfifo(path)
        obj = ledger.Ledger(path)
        self.assertIsNotNone(obj.load_error)

    def test_agent_refuses_to_unlink_a_regular_file(self):
        obj = agentlink.AgentLink(self.victim, log=lambda *_: None)
        self.assertFalse(obj.start())
        self.assertEqual(self.victim.read_text(), "private")


class GateAdmission(unittest.TestCase):
    def setUp(self):
        # Reuse the existing synthetic kernel tree, not its inherited tests.
        self.fixture = GateOpenScope()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.server = self.fixture.gate
        self.usb = self.fixture.usb
        self.node = self.fixture.dev / "input/event5"

    def temporary(self, value=1):
        return self.server._do_authorize(protocol.Request(protocol.REQ_AUTHORIZE, str(self.usb), value))

    def test_final_admission_grants_no_input_read_or_deauthorization_right(self):
        self.assertTrue(self.temporary().ok)
        self.assertIsNotNone(self.server._open_scope_parent_of(self.node))
        self.assertTrue(self.temporary(0).ok)
        req = protocol.Request(protocol.REQ_ADMIT, str(self.usb), 1, self.server._instance(self.usb))
        self.assertTrue(self.server._do_admit(req).ok)
        self.assertIsNone(self.server._open_scope_parent_of(self.node))
        self.assertFalse(self.temporary(0).ok)

    def test_temporary_activation_refuses_a_different_instance(self):
        """
        Stage 3 and 4 switch a device on by its inspected instance. A device
        that re-enumerated at the same port is a different directory inode,
        and the gate must not switch it on in the inspected one's place.
        """
        stale = protocol.Request(protocol.REQ_AUTHORIZE, str(self.usb), 1,
                                 (0, 0))
        resp = self.server._do_authorize(stale)
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("changed since inspection", resp.detail)
        self.assertEqual((self.usb / "authorized").read_text().strip(), "0")
        current = protocol.Request(protocol.REQ_AUTHORIZE, str(self.usb), 1,
                                   self.server._instance(self.usb))
        self.assertTrue(self.server._do_authorize(current).ok)

    def test_interface_ancestor_is_skipped_to_find_the_usb_device(self):
        intf = self.usb / "1-1:1.0"
        intf.mkdir()
        (intf / "authorized").write_text("1")
        (self.fixture.busview / intf.name).symlink_to(intf)
        link = self.fixture.cls / "input/event5/device"
        link.unlink()
        link.symlink_to(intf)
        self.assertTrue(self.temporary().ok)
        self.assertEqual(self.server._open_scope_parent_of(self.node), self.usb)

    def test_stale_approval_does_not_authorize_a_replacement(self):
        old = self.server._instance(self.usb)
        # Retain the original inode so the replacement cannot reuse it.
        self.usb.rename(self.usb.with_name("old-device"))
        self.usb.mkdir()
        (self.usb / "authorized").write_text("0")
        req = protocol.Request(protocol.REQ_ADMIT, str(self.usb), 1, old)
        self.assertFalse(self.server._do_admit(req).ok)
        self.assertEqual((self.usb / "authorized").read_text(), "0")

    def test_temporary_scope_does_not_transfer_to_replacement(self):
        self.assertTrue(self.temporary().ok)
        self.usb.rename(self.usb.with_name("old-device"))
        self.usb.mkdir()
        (self.usb / "authorized").write_text("1")
        self.assertIsNone(self.server._open_scope_parent_of(self.node))
        self.assertFalse(self.temporary(0).ok)

    def test_gate_disconnect_reblocks_temporary_device(self):
        self.assertTrue(self.temporary().ok)
        sock = mock.Mock()
        sock.recv.return_value = b""
        self.server.sock = sock
        self.server.serve_forever()
        self.assertEqual((self.usb / "authorized").read_text().strip(), "0")

    def test_device_operation_cannot_bypass_interface_scope(self):
        intf = self.fixture.other / "1-2:1.0"
        intf.mkdir()
        (intf / "authorized").write_text("0")
        (self.fixture.busview / intf.name).symlink_to(intf)
        req = protocol.Request(protocol.REQ_AUTHORIZE, str(intf), 1)
        self.assertFalse(self.server._do_authorize(req).ok)

    def test_direct_admission_rejects_a_changed_inode(self):
        with self.assertRaises(OSError):
            sysfs._DirectBackend().admit(self.usb, (0, 0))
        self.assertEqual((self.usb / "authorized").read_text().strip(), "0")

    def test_admission_instance_crosses_the_real_protocol(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        a.settimeout(1)
        self.server.sock = b
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        try:
            GateClient(a).admit(self.usb, self.server._instance(self.usb))
            self.assertEqual((self.usb / "authorized").read_text().strip(), "1")
            self.assertIsNone(self.server._open_scope_parent_of(self.node))
        finally:
            a.close()
            thread.join(1)
            b.close()


class MalformedMessages(unittest.TestCase):
    def test_agent_non_objects_and_deep_json_do_not_crash(self):
        link = agentlink.AgentLink()
        for data in (b"[]", b"null", b"1", b"[" * 2000 + b"]" * 2000):
            self.assertIsNone(link._parse_answer(data, 1))

    def test_protocol_refuses_nul_boolean_and_deep_json(self):
        for data in (b'{"kind":"authorize","path":"x\\u0000"}',
                     b'{"kind":"authorize","value":true}',
                     b"[" * 2000 + b"]" * 2000):
            with self.assertRaises(ValueError):
                protocol.Request.decode(data)

    def test_unsolicited_agent_flood_has_a_bound(self):
        link = agentlink.AgentLink(log=lambda *_: None)
        conn = mock.Mock()
        conn.recv.return_value = b"x" * agentlink.MAX_MESSAGE
        link._conn = conn
        discarded = link._drain(conn)
        self.assertEqual(discarded, agentlink.MAX_MESSAGE * 4)
        conn.close.assert_called_once()

    def test_protocol_rejects_oversized_valid_prefix_packet(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        server = gate_server.GateServer(b)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        a.settimeout(1)
        packet = b'{"kind":"ping"}' + b" " * protocol.MAX_MESSAGE
        a.send(packet)
        self.assertFalse(protocol.Response.decode(a.recv(protocol.MAX_MESSAGE)).ok)
        a.close()
        thread.join(1)

    def test_client_serializes_concurrent_requests(self):
        client = GateClient(mock.Mock())
        active = 0
        max_active = 0
        def exchange(*_):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            time.sleep(0.01)
            active -= 1
            return protocol.Response(protocol.OK), None
        with mock.patch.object(client, "_exchange", side_effect=exchange):
            threads = [threading.Thread(target=client.ping) for _ in range(3)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(max_active, 1)


# ---------------------------------------------------------------------------
# REQ_TRUST: "always" under --privsep, written by the root gate
# ---------------------------------------------------------------------------

class TrustRequestShape(unittest.TestCase):
    """protocol.decode refuses anything that is not a bounded TRUST request."""

    GOOD = {"kind": "trust", "path": "/sys/bus/usb/devices/1-1",
            "instance": [1, 2], "key": "0951:1666:S#ab", "label": "Stick"}

    def _decode(self, **changes):
        import json
        obj = dict(self.GOOD)
        for name, value in changes.items():
            if value is _MISSING:
                obj.pop(name)
            else:
                obj[name] = value
        return protocol.Request.decode(json.dumps(obj).encode())

    def test_a_trust_request_round_trips(self):
        req = protocol.Request(protocol.REQ_TRUST, path="/x", instance=(1, 2),
                               key="k#h", label="Stick")
        back = protocol.Request.decode(req.encode())
        self.assertEqual((back.kind, back.path, back.instance, back.key,
                          back.label),
                         (protocol.REQ_TRUST, "/x", (1, 2), "k#h", "Stick"))

    def test_key_and_label_must_be_strings(self):
        for name in ("key", "label"):
            for bad in (5, ["a"], True, {"a": 1}, 1.5):
                with self.subTest(field=name, value=bad), \
                        self.assertRaises(ValueError):
                    self._decode(**{name: bad})

    def test_nul_is_refused_in_key_and_label(self):
        for name in ("key", "label"):
            with self.subTest(field=name), self.assertRaises(ValueError):
                self._decode(**{name: "a\x00b"})

    def test_key_and_label_are_bounded(self):
        self.assertEqual(len(self._decode(key="k" * protocol.MAX_KEY).key),
                         protocol.MAX_KEY)
        self.assertEqual(
            len(self._decode(label="l" * protocol.MAX_LABEL).label),
            protocol.MAX_LABEL)
        with self.assertRaises(ValueError):
            self._decode(key="k" * (protocol.MAX_KEY + 1))
        with self.assertRaises(ValueError):
            self._decode(label="l" * (protocol.MAX_LABEL + 1))

    def test_every_field_is_required_for_trust(self):
        for name in ("path", "instance", "key", "label"):
            with self.subTest(missing=name), self.assertRaises(ValueError):
                self._decode(**{name: _MISSING})
        with self.assertRaises(ValueError):
            self._decode(path="")

    def test_an_honest_worst_case_request_fits_in_one_datagram(self):
        """Longest cleaned serial and label, every character escaped on the
        wire: still one datagram the gate will accept."""
        serial = textsafe.sanitize("\U0001f600" * 500).text
        key = f"0951:1666:{serial}#{'f' * 64}"
        req = protocol.Request(
            protocol.REQ_TRUST,
            path="/sys/devices/pci0000:00/0000:00:14.0/usb3/3-10/3-10.4/3-10.4.1",
            instance=(2 ** 63, 2 ** 63), key=key,
            label="\U0001f600" * protocol.MAX_LABEL)
        data = req.encode()
        self.assertLessEqual(len(data), protocol.MAX_MESSAGE)
        self.assertEqual(protocol.Request.decode(data).key, key)

    def test_the_contract_lists_the_operation(self):
        """The module docstring is the auditable list of what root will do."""
        self.assertRegex(protocol.__doc__, r"\n\s+TRUST\s")

    def test_a_long_label_is_cut_by_the_client_not_refused_by_the_gate(self):
        """Two maximum-length device strings joined exceed MAX_LABEL."""
        client = GateClient(mock.Mock())
        sent = []
        with mock.patch.object(
                client, "_exchange",
                side_effect=lambda req, _fd=False: sent.append(req) or
                (protocol.Response(protocol.OK), None)):
            client.trust("/x", (1, 2), "k", "x" * 300)
        label = protocol.Request.decode(sent[0].encode()).label
        self.assertEqual(len(label), protocol.MAX_LABEL)
        self.assertTrue(label.endswith("..."))


_MISSING = object()


class _GateTrustCase(unittest.TestCase):
    """
    A blocked USB device with the attributes load_device reads, linked from a
    bus view, and a trust store path in a directory the test owns.
    """

    SERIAL = "AABBCC"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.devices = root / "sys/devices"
        self.busview = root / "sys/bus/usb/devices"
        self.busview.mkdir(parents=True)
        self.usb = self.devices / "pci0/usb1/1-1"
        self._populate(self.usb, descriptor_blob((0x08, 0x06, 0x50)))
        os.symlink(self.usb, self.busview / "1-1")
        state = root / "state"
        state.mkdir(mode=0o755)
        self.trust_path = state / "trusted.json"
        for attr, value in (("USB_REAL_PREFIX", str(self.devices) + "/"),
                            ("USB_LINK_PREFIX", str(self.busview) + "/")):
            p = mock.patch.object(gate_server, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.gate = self._gate(self.trust_path)

    def _populate(self, directory, blob, serial=None):
        directory.mkdir(parents=True)
        (directory / "authorized").write_text("0\n")
        (directory / "idVendor").write_text("0951\n")
        (directory / "idProduct").write_text("1666\n")
        (directory / "descriptors").write_bytes(blob)
        serial = self.SERIAL if serial is None else serial
        if serial is not _MISSING:
            (directory / "serial").write_text(serial + "\n")

    def _gate(self, trust_path):
        return gate_server.GateServer(sock=None, log=lambda *_a: None,
                                      trust_path=trust_path)

    def instance(self):
        st = self.usb.stat()
        return (st.st_dev, st.st_ino)

    def analyzer_key(self):
        """What the daemon sends: trust.key_for over sysfs.load_device."""
        return trust.key_for(sysfs.load_device(self.busview / "1-1"))

    def temporary(self, value):
        resp = self.gate._do_authorize(protocol.Request(
            protocol.REQ_AUTHORIZE, path=str(self.usb), value=value))
        self.assertTrue(resp.ok, resp.detail)

    def admit(self):
        resp = self.gate._do_admit(protocol.Request(
            protocol.REQ_ADMIT, path=str(self.usb), value=1,
            instance=self.instance()))
        self.assertTrue(resp.ok, resp.detail)

    def ask(self, key=None, label="Kingston DataTraveler", instance=None,
            path=None):
        """One TRUST request, through the wire format's own validation."""
        req = protocol.Request(
            protocol.REQ_TRUST, path=str(path or self.usb),
            instance=instance or self.instance(),
            key=self.analyzer_key() if key is None else key, label=label)
        return self.gate._do_trust(protocol.Request.decode(req.encode()))

    def stored(self):
        store = trust.TrustStore(self.trust_path)
        self.assertIsNone(store.load_error)
        return store.devices


class GateFingerprintIsTheAnalyzersKey(_GateTrustCase):
    """
    The gate never takes the key from the analyzer; it computes its own and
    only compares. That is worth nothing unless an honest analyzer's key and
    the gate's are equal to the byte -- including the serial, which the
    analyzer passes through textsafe before it ever reaches the key.
    """

    def _gate_key(self):
        self.temporary(1)          # the snapshot is taken by the first switch-on
        return self.gate._fingerprints[str(self.usb)][1]

    def test_the_mirrored_bound_agrees_with_sysfs(self):
        self.assertEqual(gate_server.MAX_DESCRIPTOR_BYTES,
                         sysfs.MAX_DESCRIPTOR_BYTES)

    def test_equal_for_an_ordinary_device(self):
        key, identity, digest = self._gate_key()
        dev = sysfs.load_device(self.busview / "1-1")
        self.assertEqual(key, trust.key_for(dev))
        self.assertEqual(identity, trust.identity_of(dev))
        self.assertEqual(digest, trust.descriptor_hash(dev))

    def test_equal_when_textsafe_rewrites_the_serial(self):
        raw = "SN\x1b[2J\x07\x7f42"
        (self.usb / "serial").write_text(f"  {raw}  \n")
        self.assertNotEqual(textsafe.sanitize(raw).text, raw,
                            "the fixture must be a serial textsafe changes")
        key = self._gate_key()[0]
        self.assertEqual(key, trust.key_for(sysfs.load_device(self.usb)))
        self.assertIn(textsafe.sanitize(raw).text, key)
        self.assertNotIn("\x1b", key)

    def test_equal_when_the_serial_is_not_utf8(self):
        """Both halves decode the same way; neither raises on it any more."""
        (self.usb / "serial").write_bytes(b"SN\xff\xfe42\n")
        key = self._gate_key()[0]
        self.assertIsNotNone(key)
        self.assertEqual(key, trust.key_for(sysfs.load_device(self.usb)))

    def test_equal_when_there_is_no_serial(self):
        (self.usb / "serial").unlink()
        key = self._gate_key()[0]
        self.assertEqual(key, trust.key_for(sysfs.load_device(self.usb)))
        self.assertTrue(key.startswith("0951:1666:-#"))

    def test_no_descriptors_means_no_key_on_either_side(self):
        (self.usb / "descriptors").unlink()
        self.assertIsNone(self._gate_key())
        self.assertIsNone(trust.key_for(sysfs.load_device(self.usb)))

    def test_a_symlinked_attribute_is_not_followed(self):
        decoy = Path(self.tmp.name) / "decoy"
        decoy.write_text("DECOY\n")
        (self.usb / "serial").unlink()
        (self.usb / "serial").symlink_to(decoy)
        key = self._gate_key()[0]
        self.assertNotIn("DECOY", key)


class GateTrust(_GateTrustCase):

    # -- the round of a legitimate "always" ------------------------------

    def test_an_admitted_device_is_remembered(self):
        self.admit()
        resp = self.ask(label="My stick")
        self.assertTrue(resp.ok, resp.detail)
        entry = self.stored()[self.analyzer_key()]
        import hashlib
        self.assertEqual(entry.identity, f"0951:1666:{self.SERIAL}")
        self.assertEqual(entry.descriptor_hash, hashlib.sha256(
            (self.usb / "descriptors").read_bytes()).hexdigest())
        self.assertEqual(entry.label, "My stick")
        self.assertEqual((entry.times_admitted, entry.ports, entry.note),
                         (1, ["1-1"], ""))
        self.assertEqual(entry.trusted_at, entry.last_seen)
        self.assertLess(abs(entry.trusted_at - time.time()), 60)

    def test_a_new_store_is_readable_by_the_analyzer_and_never_writable(self):
        self.admit()
        self.assertTrue(self.ask().ok)
        self.assertEqual(self.trust_path.stat().st_mode & 0o777, 0o644)

    def test_the_fingerprint_is_the_one_from_before_the_first_switch_on(self):
        """A device that changes its story once running is not re-measured."""
        before = self.analyzer_key()
        self.temporary(1)          # quarantine / storage scan
        (self.usb / "descriptors").write_bytes(
            descriptor_blob((0x03, 0x01, 0x01)))
        self.temporary(0)          # re-blocked for the question
        after = self.analyzer_key()
        self.assertNotEqual(before, after)
        self.admit()
        self.assertEqual(self.ask(key=after).status, protocol.DENIED)
        self.write_authorized("0")
        self.admit()
        self.assertTrue(self.ask(key=before).ok)

    def test_a_new_device_at_the_port_is_measured_afresh(self):
        self.temporary(1)
        self.temporary(0)
        self.usb.rename(self.usb.with_name("gone"))   # keep the old inode
        self._populate(self.usb, descriptor_blob((0x03, 0x01, 0x02)),
                       serial="OTHER")
        self.admit()
        self.assertTrue(self.ask().ok)
        self.assertIn(self.analyzer_key(), self.stored())

    def write_authorized(self, value):
        (self.usb / "authorized").write_text(value + "\n")

    # -- scope: only what this gate admitted, now, once -------------------

    def test_a_device_this_gate_never_admitted_is_refused(self):
        self.write_authorized("1")
        resp = self.ask()
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("not admitted", resp.detail)
        self.assertFalse(self.trust_path.exists())

    def test_a_temporary_switch_on_is_not_an_admission(self):
        self.temporary(1)
        self.assertEqual(self.ask().status, protocol.DENIED)

    def test_a_wrong_instance_is_refused_without_spending_the_admission(self):
        self.admit()
        self.assertEqual(self.ask(instance=(0, 0)).status, protocol.DENIED)
        self.assertTrue(self.ask().ok)

    def test_a_device_replaced_since_admission_is_refused(self):
        self.admit()
        admitted = self.instance()
        self.usb.rename(self.usb.with_name("gone"))
        self._populate(self.usb, descriptor_blob((0x08, 0x06, 0x50)))
        self.write_authorized("1")
        resp = self.ask(instance=admitted)
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("changed", resp.detail)
        self.assertFalse(self.trust_path.exists())

    def test_the_window_closes(self):
        self.admit()
        instance, _at = self.gate._admitted[str(self.usb)]
        self.gate._admitted[str(self.usb)] = (
            instance, time.monotonic() - gate_server.TRUST_WINDOW - 1)
        resp = self.ask()
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertFalse(self.trust_path.exists())

    def test_it_is_one_shot(self):
        self.admit()
        self.assertTrue(self.ask().ok)
        self.assertEqual(self.ask().status, protocol.DENIED)

    def test_a_refused_attempt_spends_it_too(self):
        """A failure is not an invitation to try other keys."""
        self.admit()
        self.assertEqual(self.ask(key="0951:1666:x#00").status, protocol.DENIED)
        self.assertEqual(self.ask().status, protocol.DENIED)
        self.assertFalse(self.trust_path.exists())

    def test_a_device_switched_off_since_admission_is_refused(self):
        self.admit()
        self.write_authorized("0")
        resp = self.ask()
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("no longer authorized", resp.detail)

    def test_a_re_block_through_the_gate_ends_the_admission(self):
        self.admit()
        self.gate._media_hosts[str(self.usb)] = self.instance()
        self.gate.watch_media = True
        with mock.patch.object(self.gate, "_storage_only", return_value=True):
            self.temporary(0)      # a media-policy hit
        self.assertNotIn(str(self.usb), self.gate._admitted)

    def test_a_path_outside_the_usb_tree_is_refused(self):
        self.admit()
        self.assertEqual(self.ask(path="/etc/shadow").status, protocol.DENIED)

    # -- what is stored is the gate's own measurement ---------------------

    def test_a_key_that_is_not_the_gates_is_refused(self):
        self.admit()
        identity = f"0951:1666:{self.SERIAL}"
        resp = self.ask(key=f"{identity}#{'0' * 64}")
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("fingerprint does not match", resp.detail)
        self.assertFalse(self.trust_path.exists())

    def test_an_unmeasurable_device_cannot_be_trusted(self):
        (self.usb / "descriptors").unlink()
        self.admit()
        resp = self.ask(key=f"0951:1666:{self.SERIAL}#{'0' * 64}")
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertFalse(self.trust_path.exists())

    def test_control_characters_in_the_label_never_reach_the_store(self):
        """Cleaned by the gate itself, whatever the analyzer sent."""
        for label in ("evil\x1b[2J", "bell\x07", "del\x7f", "c1\x85",
                      "line\u2028break", "bidi\u202e"):
            with self.subTest(label=label):
                self.write_authorized("0")
                self.admit()
                self.assertTrue(self.ask(label=label).ok)
                stored = self.stored()[self.analyzer_key()].label
                self.assertEqual(stored, textsafe.sanitize(label).text)
                self.assertFalse(any(ord(c) < 0x20 or 0x7f <= ord(c) < 0xa0
                                     or c in "\u2028\u202e" for c in stored),
                                 repr(stored))

    def test_a_label_cut_short_by_textsafe_is_kept_not_refused(self):
        """
        The daemon's own label for a device whose product string textsafe
        cut short. Such a label once came back different from a second
        cleaning -- the cut skipped an escape that did not fit and went on
        appending -- and the gate refusing it lost "always" with the
        admission already spent. The gate cleans and keeps it.
        """
        product = "A" * 118 + "\u0301" * 3 + "\ufeff" + "\u0301"
        label = textsafe.sanitize(product).text
        self.admit()
        resp = self.ask(label=label)
        self.assertTrue(resp.ok, resp.detail)
        self.assertEqual(self.stored()[self.analyzer_key()].label, label)

    def test_a_label_textsafe_already_cleaned_is_accepted(self):
        """What the daemon really sends: escapes as visible text."""
        label = textsafe.sanitize("Acme\x1b[2J").text + " Widget é"
        self.admit()
        self.assertTrue(self.ask(label=label).ok)
        self.assertEqual(self.stored()[self.analyzer_key()].label, label)

    # -- the store -------------------------------------------------------

    def test_trust_disabled_is_refused(self):
        self.gate = self._gate(None)
        self.admit()
        resp = self.ask()
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("disabled", resp.detail)

    def test_a_missing_directory_is_not_created(self):
        """Made here, its mode would be root's umask's to decide, and a 0700
        directory is one the analyzer can read nothing back from."""
        missing = Path(self.tmp.name) / "absent" / "trusted.json"
        self.gate = self._gate(missing)
        self.admit()
        resp = self.ask()
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertIn("does not exist", resp.detail)
        self.assertFalse(missing.parent.exists())

    def test_a_store_that_cannot_be_vouched_for_is_not_rewritten(self):
        for text, mode in (('{"schema": 1, "devices": {}}', 0o664),
                           ("{not json", 0o600)):
            with self.subTest(mode=oct(mode)):
                self.trust_path.write_text(text)
                os.chmod(self.trust_path, mode)
                self.write_authorized("0")
                self.admit()
                resp = self.ask()
                self.assertEqual(resp.status, protocol.DENIED)
                self.assertEqual(self.trust_path.read_text(), text)
                self.assertEqual(self.trust_path.stat().st_mode & 0o777, mode)

    def _fill(self, keys):
        store = trust.TrustStore(self.trust_path)
        for key in keys:
            store.devices[key] = trust.TrustedDevice(
                key=key, identity="v:p:s", label="filler",
                descriptor_hash="ab", trusted_at=1.0, last_seen=1.0)
        self.assertIsNone(store.save())

    def test_the_store_has_a_ceiling(self):
        self._fill(["a#1", "b#2"])
        self.admit()
        with mock.patch.object(gate_server, "MAX_TRUSTED", 2):
            resp = self.ask()
        self.assertEqual(resp.status, protocol.DENIED)
        self.assertEqual(set(self.stored()), {"a#1", "b#2"})

    def test_re_trusting_a_key_already_there_is_allowed_at_the_ceiling(self):
        self._fill(["a#1", self.analyzer_key()])
        self.admit()
        with mock.patch.object(gate_server, "MAX_TRUSTED", 2):
            resp = self.ask(label="Renamed")
        self.assertTrue(resp.ok, resp.detail)
        devices = self.stored()
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[self.analyzer_key()].label, "Renamed")

    def test_an_existing_store_keeps_its_entries_and_mode(self):
        self._fill(["a#1"])
        os.chmod(self.trust_path, 0o600)
        self.admit()
        self.assertTrue(self.ask().ok)
        self.assertEqual(set(self.stored()), {"a#1", self.analyzer_key()})
        self.assertEqual(self.trust_path.stat().st_mode & 0o777, 0o600)

    def test_the_handler_answers_rather_than_raises(self):
        self.admit()
        with mock.patch.object(gate_server.trust_mod, "TrustStore",
                               side_effect=OSError("disk on fire")):
            resp = self.ask()
        self.assertEqual(resp.status, protocol.ERROR)

    def test_the_serve_loop_routes_the_request(self):
        self.admit()
        req = protocol.Request(protocol.REQ_TRUST, path=str(self.usb),
                               instance=self.instance(),
                               key=self.analyzer_key(), label="Stick")
        sock = mock.Mock()
        sock.recv.side_effect = [req.encode(), b""]
        self.gate.sock = sock
        self.gate.serve_forever()
        reply = protocol.Response.decode(sock.sendmsg.call_args.args[0][0])
        self.assertTrue(reply.ok, reply.detail)


class GateTrustRoundTrip(_GateTrustCase):
    """
    The whole path the daemon takes under --privsep, over a real socketpair:
    sysfs.admit_device and sysfs.remember_via_backend through an installed
    GateBackend, and a store that a FRESH TrustStore -- the next run of the
    analyzer -- reads back as trusting this exact device.
    """

    def setUp(self):
        super().setUp()
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        a.settimeout(2)
        self.gate.sock = b
        thread = threading.Thread(target=self.gate.serve_forever, daemon=True)
        thread.start()

        def stop():
            a.close()
            thread.join(2)
            b.close()
        self.addCleanup(stop)
        self.client = GateClient(a)
        previous = sysfs._backend
        sysfs.install_backend(gate_client.GateBackend(self.client))
        self.addCleanup(sysfs.install_backend, previous)
        # Read at the uevent, while blocked, as the daemon does.
        self.dev = sysfs.load_device(self.busview / "1-1")

    def test_always_survives_a_restart(self):
        self.assertTrue(sysfs.backend_can_trust())
        sysfs.admit_device(self.dev)
        sysfs.remember_via_backend(self.dev, trust.key_for(self.dev),
                                   self.dev.label())
        fresh = trust.TrustStore(self.trust_path)
        self.assertIsNone(fresh.load_error)
        self.assertTrue(fresh.is_trusted(sysfs.load_device(self.usb)))
        self.assertEqual(self.trust_path.stat().st_mode & 0o777, 0o644)

    def test_a_refusal_reaches_the_daemon_as_an_oserror(self):
        sysfs.admit_device(self.dev)
        with self.assertRaises(OSError) as caught:
            sysfs.remember_via_backend(self.dev, "0951:1666:x#00", "Stick")
        self.assertIsInstance(caught.exception, gate_client.GateError)
        self.assertIn("fingerprint", str(caught.exception))
        self.assertFalse(self.trust_path.exists())

    def test_a_second_request_for_one_admission_is_refused(self):
        sysfs.admit_device(self.dev)
        key = trust.key_for(self.dev)
        sysfs.remember_via_backend(self.dev, key, "Stick")
        with self.assertRaises(gate_client.GateError):
            sysfs.remember_via_backend(self.dev, key, "Stick")

    def test_the_direct_backend_does_not_claim_to_trust(self):
        sysfs.install_backend(sysfs._DirectBackend())
        self.assertFalse(sysfs.backend_can_trust())
        with self.assertRaises(OSError):
            sysfs.remember_via_backend(self.dev, "k#h", "Stick")

    def test_a_backend_with_a_merely_truthy_flag_does_not_claim_to_trust(self):
        sysfs.install_backend(mock.Mock())
        self.assertFalse(sysfs.backend_can_trust())


class TrustPathComesFromTheRootSide(unittest.TestCase):
    """__main__ -> privsep.start -> run_gate -> GateServer, never the socket."""

    def _main(self, argv):
        from probolos import __main__ as cli
        captured = {}

        def fake_start(analyzer_main, **kwargs):
            captured.update(kwargs)
            return 0

        with mock.patch.object(cli, "require_usb"), \
                mock.patch.object(cli, "require_root"), \
                mock.patch.object(cli, "claim_the_gate"), \
                mock.patch.object(privsep, "prepare_trust_readable"), \
                mock.patch.object(privsep, "start", fake_start), \
                mock.patch("builtins.print"):
            with self.assertRaises(SystemExit):
                cli.main(argv)
        return captured

    def test_the_cli_hands_the_trust_path_to_the_gate(self):
        captured = self._main(["--privsep", "--no-ledger", "--trust-file",
                               "/var/lib/probolos/t.json"])
        self.assertEqual(str(captured["trust_path"]),
                         "/var/lib/probolos/t.json")

    def test_no_trust_means_no_trust_path(self):
        captured = self._main(["--privsep", "--no-ledger", "--no-trust"])
        self.assertIsNone(captured["trust_path"])

    def test_start_forwards_it_to_the_gate(self):
        seen = {}

        def fake_run_gate(sock, log, watch_media, trust_path=None):
            seen["trust_path"] = trust_path

        with mock.patch.object(privsep.os, "getuid", return_value=0), \
                mock.patch.object(privsep, "resolve_user",
                                  return_value=(65534, 65534)), \
                mock.patch.object(privsep.os, "fork", return_value=4242), \
                mock.patch.object(privsep.os, "waitpid",
                                  return_value=(4242, 0)), \
                mock.patch("signal.signal"), \
                mock.patch.object(privsep.gate_server, "run_gate",
                                  fake_run_gate):
            rc = privsep.start(lambda _c: 0, log=lambda *_a: None,
                               trust_path="/var/lib/probolos/trusted.json")
        self.assertEqual(rc, 0)
        self.assertEqual(seen["trust_path"], "/var/lib/probolos/trusted.json")

    def test_the_gate_keeps_it(self):
        gate = gate_server.GateServer(sock=None, log=lambda *_a: None,
                                      trust_path="/var/lib/probolos/t.json")
        self.assertEqual(gate.trust_path, Path("/var/lib/probolos/t.json"))
        self.assertIsNone(gate_server.GateServer(sock=None).trust_path)


if __name__ == "__main__":
    unittest.main()
