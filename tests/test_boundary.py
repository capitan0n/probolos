"""
The refusal and error paths of the privilege boundary.

test_privsep.py proves the boundary does what it should. This file proves it
fails the way it should: every OSError, every refusal and every fork, drop or
wait error on the root side ends in a refusal, an error response or an exit
status -- never an exception that escapes the gate, and never an approval.

Most of it runs without root. privsep.start() is driven in-process with
fork(), _exit() and the gate mocked, because the forked children of the real
start() do not report coverage (see ROADMAP 1.1); the real fork is exercised
by test_privsep.AnalyzerHasNoControllingTerminal.

Covers probolos.privsep, probolos.gate_client and probolos.gate_server.
"""

from __future__ import annotations

import fcntl
import os
import signal
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from probolos import gate_server, privsep, protocol
from probolos.gate_client import GateBackend, GateClient, GateError


# ---------------------------------------------------------------------------
# privsep: dropping privilege
# ---------------------------------------------------------------------------

class DropPrivilegesVerifiesEveryStep(unittest.TestCase):
    """
    The drop is asserted, not assumed. Each check is driven with the system
    calls mocked to report a drop that did not take.
    """

    def drop(self, *, uid=65534, gid=65534, euid=None, egid=None,
             groups=None, regain=False):
        euid = uid if euid is None else euid
        egid = gid if egid is None else egid
        groups = [gid] if groups is None else groups

        def setuid(value):
            if value == 0 and not regain:
                raise PermissionError("not permitted")

        setuid_mock = mock.Mock(side_effect=setuid)
        with mock.patch.multiple(
                privsep.os,
                getuid=mock.Mock(side_effect=[0, uid, uid]),
                geteuid=mock.Mock(return_value=euid),
                getgid=mock.Mock(return_value=gid),
                getegid=mock.Mock(return_value=egid),
                getgroups=mock.Mock(return_value=groups),
                setgroups=mock.DEFAULT, setgid=mock.DEFAULT,
                setuid=setuid_mock) as calls:
            privsep.drop_privileges(65534, 65534)
        calls["setuid"] = setuid_mock
        return calls

    def test_a_clean_drop_passes_in_the_documented_order(self):
        calls = self.drop()
        calls["setgroups"].assert_called_once_with([])
        calls["setgid"].assert_called_once_with(65534)
        self.assertEqual(calls["setuid"].call_args_list,
                         [mock.call(65534), mock.call(0)])

    def test_an_effective_uid_left_behind_stops_it(self):
        with self.assertRaisesRegex(privsep.PrivsepError, "uid did not drop"):
            self.drop(euid=0)

    def test_a_gid_left_behind_stops_it(self):
        with self.assertRaisesRegex(privsep.PrivsepError, "gid did not drop"):
            self.drop(egid=0)

    def test_root_regained_after_the_drop_stops_it(self):
        with self.assertRaisesRegex(privsep.PrivsepError, "regained root"):
            self.drop(regain=True)

    def test_not_root_to_begin_with_changes_nothing(self):
        with mock.patch.object(privsep.os, "getuid", return_value=1000), \
                mock.patch.object(privsep.os, "setuid") as setuid:
            privsep.drop_privileges(65534, 65534)
        setuid.assert_not_called()


class AnalyzerExitStatus(unittest.TestCase):
    """_run_analyzer turns every ending into a status; nothing escapes."""

    def test_ctrl_c_is_a_clean_exit(self):
        def interrupted(_client):
            raise KeyboardInterrupt
        self.assertEqual(privsep._run_analyzer(interrupted, None), 0)

    def test_a_system_exit_with_a_message_is_a_failure(self):
        def leaves(_client):
            raise SystemExit("a panic file is still there")
        with mock.patch("sys.stderr") as err:
            self.assertEqual(privsep._run_analyzer(leaves, None), 1)
        self.assertIn("panic file", "".join(
            c.args[0] for c in err.write.call_args_list))

    def test_a_crash_is_a_failure(self):
        def crashes(_client):
            raise RuntimeError("boom")
        with mock.patch("sys.stderr"):
            self.assertEqual(privsep._run_analyzer(crashes, None), 1)

    def test_a_normal_return_is_its_status(self):
        self.assertEqual(privsep._run_analyzer(lambda _c: None, None), 0)
        self.assertEqual(privsep._run_analyzer(lambda _c: 4, None), 4)


# ---------------------------------------------------------------------------
# privsep: preparing files for the analyzer
# ---------------------------------------------------------------------------

class TrustFilePreparation(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.root = Path(self._d.name)

    def test_a_missing_trust_file_is_not_an_error(self):
        logged = []
        privsep.prepare_trust_readable(self.root / "trusted.json",
                                       log=logged.append)
        self.assertEqual(logged, [])

    def test_a_file_owned_by_someone_else_is_left_alone(self):
        target = self.root / "trusted.json"
        target.write_text("{}")
        os.chmod(target, 0o600)
        logged = []
        with mock.patch.object(privsep.os, "geteuid",
                               return_value=os.geteuid() + 1):
            privsep.prepare_trust_readable(target, log=logged.append)
        self.assertTrue(any("REFUSING" in line for line in logged))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)


class StateDirectoryPreparation(unittest.TestCase):

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.root = Path(self._d.name)
        self.state = self.root / "state"
        patcher = mock.patch.object(privsep, "STATE_ROOTS", (str(self.root),))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_existing_ledger_is_handed_over_with_its_directory(self):
        self.state.mkdir()
        ledger = self.state / "ledger.json"
        ledger.write_text("{}")
        os.chmod(ledger, 0o644)
        logged = []
        with mock.patch.object(privsep.os, "fchown") as fchown:
            privsep.prepare_state_dir(ledger, uid=4242, gid=4343,
                                      log=logged.append)
        self.assertEqual([c.args[1:] for c in fchown.call_args_list],
                         [(4242, 4343), (4242, 4343)])
        self.assertEqual(ledger.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertFalse(any("REFUSING" in line for line in logged))

    def test_a_ledger_that_is_not_a_regular_file_is_refused(self):
        self.state.mkdir()
        os.mkfifo(self.state / "ledger.json")
        logged = []
        with mock.patch.object(privsep.os, "fchown") as fchown:
            privsep.prepare_state_dir(self.state / "ledger.json", uid=4242,
                                      gid=4343, log=logged.append)
        fchown.assert_not_called()
        self.assertTrue(any("REFUSING" in line for line in logged))


# ---------------------------------------------------------------------------
# privsep.start(): driven in-process
# ---------------------------------------------------------------------------

class _Exited(BaseException):
    """os._exit(), made catchable so the child branch can be run in-process."""

    @property
    def code(self):
        return self.args[0]


def _exit(code):
    raise _Exited(code)


class _StartCase(unittest.TestCase):
    """
    start() installs signal handlers in the calling process. They are put
    back after every test, whatever the test did.
    """

    SIGNALS = (signal.SIGINT, signal.SIGHUP, signal.SIGQUIT, signal.SIGTERM,
               signal.SIGTSTP)

    def setUp(self):
        saved = {s: signal.getsignal(s) for s in self.SIGNALS}

        def restore():
            for s, handler in saved.items():
                signal.signal(s, handler)
        self.addCleanup(restore)
        patcher = mock.patch.object(privsep.os, "getuid", return_value=0)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(privsep, "resolve_user",
                                    return_value=(65534, 65534))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.logged = []


class StartRefusesWithoutRoot(unittest.TestCase):

    def test_not_root_is_an_error_before_anything_forks(self):
        with mock.patch.object(privsep.os, "getuid", return_value=1000), \
                mock.patch.object(privsep.os, "fork") as fork:
            with self.assertRaisesRegex(privsep.PrivsepError, "as root"):
                privsep.start(lambda _c: 0)
        fork.assert_not_called()


class StartParentSide(_StartCase):
    """The root half: serve the gate, then always reap the analyzer."""

    def start(self, *, status=0, gate=None, waitpid=None, **options):
        def default_wait(_pid, _flags):
            return 4242, status
        with mock.patch.object(privsep.os, "fork", return_value=4242), \
                mock.patch.object(privsep.gate_server, "run_gate",
                                  side_effect=gate) as run_gate, \
                mock.patch.object(privsep.os, "waitpid",
                                  side_effect=waitpid or default_wait):
            rc = privsep.start(lambda _c: 0, log=self.logged.append,
                               **options)
        return rc, run_gate

    def test_a_clean_analyzer_exit_is_zero(self):
        rc, run_gate = self.start(watch_media=True, trust_path="/x/t.json")
        self.assertEqual(rc, 0)
        _sock, = run_gate.call_args.args
        self.assertEqual(run_gate.call_args.kwargs["watch_media"], True)
        self.assertEqual(run_gate.call_args.kwargs["trust_path"], "/x/t.json")

    def test_the_analyzers_status_is_passed_on(self):
        rc, _ = self.start(status=3 << 8)
        self.assertEqual(rc, 3)

    def test_a_gate_that_raises_is_logged_and_the_child_still_reaped(self):
        waited = []

        def wait(pid, flags):
            waited.append(pid)
            return pid, 0
        rc, _ = self.start(gate=BrokenPipeError("analyzer gone"),
                           waitpid=wait)
        self.assertEqual(waited, [4242])
        self.assertEqual(rc, 1)
        self.assertTrue(any("stopped with an error" in line
                            for line in self.logged))

    def test_a_child_already_reaped_is_not_an_error(self):
        def gone(_pid, _flags):
            raise ChildProcessError
        rc, _ = self.start(waitpid=gone)
        self.assertEqual(rc, 0)

    def test_a_child_already_reaped_after_a_gate_error_is_a_failure(self):
        def gone(_pid, _flags):
            raise ChildProcessError
        rc, _ = self.start(gate=OSError("x"), waitpid=gone)
        self.assertEqual(rc, 1)

    def test_state_files_sharing_a_directory_are_prepared_once_loudly(self):
        with mock.patch.object(privsep, "prepare_state_dir") as prepare:
            self.start(state_paths=("/run/probolos/state/ledger.json", None,
                                    "/run/probolos/state/audit.json"))
        paths = [c.args[0] for c in prepare.call_args_list]
        self.assertEqual(paths, ["/run/probolos/state/ledger.json",
                                 "/run/probolos/state/audit.json"])
        first, second = (c.kwargs["log"] for c in prepare.call_args_list)
        self.assertEqual(first, self.logged.append)
        self.assertNotEqual(second, self.logged.append)

    def test_terminal_signals_are_forwarded_to_the_analyzer(self):
        seen = {}

        def gate(*_a, **_k):
            seen["handler"] = signal.getsignal(signal.SIGINT)
            seen["term"] = signal.getsignal(signal.SIGTERM)
        self.start(gate=gate)
        self.assertEqual(seen["term"], signal.SIG_IGN)
        with mock.patch.object(privsep.os, "kill") as kill:
            seen["handler"](signal.SIGINT, None)
        kill.assert_called_once_with(4242, signal.SIGINT)
        with mock.patch.object(privsep.os, "kill",
                               side_effect=ProcessLookupError):
            seen["handler"](signal.SIGHUP, None)    # analyzer gone: ignored

    def test_a_signal_before_fork_returns_is_dropped(self):
        """Nobody to forward to yet: dropped, not fatal to the root side."""
        with mock.patch.object(privsep.os, "kill") as kill:
            def fork():
                signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
                return 4242
            with mock.patch.object(privsep.os, "fork", side_effect=fork), \
                    mock.patch.object(privsep.gate_server, "run_gate"), \
                    mock.patch.object(privsep.os, "waitpid",
                                      return_value=(4242, 0)):
                rc = privsep.start(lambda _c: 0, log=self.logged.append)
        self.assertEqual(rc, 0)
        kill.assert_not_called()

    def test_signal_handlers_that_cannot_be_installed_do_not_stop_it(self):
        with mock.patch("signal.signal", side_effect=ValueError("not main")):
            rc, run_gate = self.start()
        self.assertEqual(rc, 0)
        run_gate.assert_called_once()


class StartChildSide(_StartCase):
    """The analyzer half: leave the session, drop, run, and only ever _exit."""

    def child(self, analyzer_main=lambda _c: 5, *, setsid=None, drop=None):
        with mock.patch.object(privsep.os, "fork", return_value=0), \
                mock.patch.object(privsep.os, "setsid",
                                  side_effect=setsid), \
                mock.patch.object(privsep, "drop_privileges",
                                  side_effect=drop) as dropped, \
                mock.patch.object(privsep.os, "_exit", side_effect=_exit), \
                mock.patch.object(privsep.gate_server, "run_gate") as gate, \
                mock.patch("sys.stderr"):
            with self.assertRaises(_Exited) as ended:
                privsep.start(analyzer_main, log=self.logged.append)
        gate.assert_not_called()
        return ended.exception.code, dropped

    def test_the_analyzers_status_is_the_exit_status(self):
        clients = []

        def analyzer(client):
            clients.append(client)
            return 5
        code, dropped = self.child(analyzer)
        self.assertEqual(code, 5)
        dropped.assert_called_once_with(65534, 65534)
        self.assertIsInstance(clients[0], GateClient)

    def test_the_inherited_signal_dispositions_are_put_back(self):
        before = signal.getsignal(signal.SIGTERM)
        seen = []
        self.child(lambda _c: seen.append(signal.getsignal(signal.SIGTERM)))
        self.assertEqual(seen, [before])

    def test_failing_to_leave_the_terminal_session_stops_the_child(self):
        ran = []
        code, dropped = self.child(lambda _c: ran.append(1),
                                   setsid=PermissionError("EPERM"))
        self.assertEqual(code, 70)
        dropped.assert_not_called()
        self.assertEqual(ran, [], "the analyzer ran on the terminal session")

    def test_failing_to_drop_privilege_stops_the_child(self):
        ran = []
        code, _ = self.child(lambda _c: ran.append(1),
                             drop=privsep.PrivsepError("groups survived"))
        self.assertEqual(code, 70)
        self.assertEqual(ran, [], "the analyzer ran as root")


# ---------------------------------------------------------------------------
# gate_client: every refusal is a GateError, every broken exchange closes
# ---------------------------------------------------------------------------

class _FakeGateSocket:
    """Answers each request with the next canned response."""

    def __init__(self, *responses, ancdata=()):
        self.responses = list(responses)
        self.ancdata = list(ancdata)
        self.sent = []
        self.closed = False

    def sendmsg(self, parts, *_ancillary):
        self.sent.append(protocol.Request.decode(parts[0]))

    def _next(self):
        response = self.responses.pop(0)
        return response if isinstance(response, bytes) else response.encode()

    def recv(self, _size):
        return self._next()

    def recvmsg(self, _size, _ancsize):
        return self._next(), self.ancdata, 0, None

    def close(self):
        self.closed = True


DENIED = protocol.Response(protocol.DENIED, "not under quarantine")
OK = protocol.Response(protocol.OK)


class GateClientRefusals(unittest.TestCase):

    def client(self, *responses, **kw):
        self.sock = _FakeGateSocket(*responses, **kw)
        return GateClient(self.sock)

    def test_every_refused_operation_raises_a_gate_error(self):
        operations = {
            "admit": lambda c: c.admit("/sys/x", (1, 2)),
            "authorize": lambda c: c.authorize("/sys/x", 1),
            "authorize_interface":
                lambda c: c.authorize_interface("/sys/x:1.0", 0),
            "set_default": lambda c: c.set_default("/sys/usb1", 1),
            "trust": lambda c: c.trust("/sys/x", (1, 2), "k", "label"),
            "open_block": lambda c: c.open_block("/dev/sdz"),
            "open_input": lambda c: c.open_input("/dev/input/event5"),
        }
        for name, call in operations.items():
            with self.subTest(name):
                client = self.client(DENIED)
                with self.assertRaisesRegex(GateError, f"{name} failed"):
                    call(client)
                self.assertFalse(self.sock.closed,
                                 "a refusal is an answer, not a broken link")

    def test_a_gate_error_is_an_os_error(self):
        """So every `except OSError` in the daemon handles both modes."""
        self.assertTrue(issubclass(GateError, OSError))

    def test_an_ok_without_a_descriptor_is_still_a_failure(self):
        client = self.client(protocol.Response(protocol.OK, has_fd=True))
        with self.assertRaisesRegex(GateError, "open_input failed"):
            client.open_input("/dev/input/event5")

    def test_a_closed_gate_is_an_error_and_closes_the_socket(self):
        for call in (lambda c: c.ping(), lambda c: c.open_block("/dev/sdz")):
            client = self.client(b"")
            with self.assertRaisesRegex(GateError, "closed the connection"):
                call(client)
            self.assertTrue(self.sock.closed)

    def test_an_undecodable_reply_closes_the_socket(self):
        """A stale reply must never be read as the next operation's."""
        client = self.client(b'{"status": "maybe"}')
        with self.assertRaises(ValueError):
            client.ping()
        self.assertTrue(self.sock.closed)

    def test_ancillary_data_that_is_not_a_descriptor_is_ignored(self):
        client = self.client(
            protocol.Response(protocol.OK, has_fd=True),
            ancdata=[(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, b"\0" * 12),
                     (socket.SOL_SOCKET, socket.SCM_RIGHTS, b"\0\0")])
        with self.assertRaisesRegex(GateError, "open_block failed"):
            client.open_block("/dev/sdz")

    def test_a_granted_descriptor_is_returned(self):
        fds = [os.open(os.devnull, os.O_RDONLY) for _ in range(2)]
        for fd in fds:
            self.addCleanup(os.close, fd)
        for fd, call in zip(fds, (lambda c: c.open_input("/dev/input/e5"),
                                  lambda c: c.open_block("/dev/sdz")),
                            strict=True):
            client = self.client(
                protocol.Response(protocol.OK, has_fd=True),
                ancdata=[(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                          fd.to_bytes(4, "little", signed=True))])
            self.assertEqual(call(client), fd)

    def test_an_accepted_operation_returns_quietly(self):
        client = self.client(OK, OK, OK, OK)
        client.authorize("/sys/x", 1)
        client.authorize_interface("/sys/x:1.0", 1)
        client.set_default("/sys/usb1", 0)
        self.assertTrue(client.ping())
        self.assertFalse(self.sock.closed)

    def test_a_label_too_long_for_the_protocol_is_cut(self):
        client = self.client(OK)
        client.trust("/sys/x", (1, 2), "k", "x" * (protocol.MAX_LABEL + 50))
        label = self.sock.sent[0].label
        self.assertEqual(len(label), protocol.MAX_LABEL)
        self.assertTrue(label.endswith("..."))


class GateBackendRoutesEverythingThroughTheClient(unittest.TestCase):

    def test_each_operation_reaches_the_client(self):
        client = mock.Mock()
        backend = GateBackend(client)
        backend.admit("/p", (1, 2))
        backend.authorize("/p", 0)
        backend.authorize_interface("/p:1.0", 1)
        backend.set_default("/usb1", 0)
        backend.open_input("/dev/input/event1")
        backend.open_block("/dev/sdz")
        backend.trust("/p", (1, 2), "k", "l")
        self.assertEqual([c[0] for c in client.method_calls], [
            "admit", "authorize", "authorize_interface", "set_default",
            "open_input", "open_block", "trust"])

    def test_bus_wide_operations_are_not_offered(self):
        backend = GateBackend(mock.Mock())
        self.assertFalse(backend.supports_bus_wide)
        with self.assertRaises(NotImplementedError):
            backend.set_drivers_autoprobe(0)
        with self.assertRaises(NotImplementedError):
            backend.trigger_driver_probe("1-1")



# ---------------------------------------------------------------------------
# gate_server: refusal and error paths
# ---------------------------------------------------------------------------

def _req(kind, path, value=0, **fields):
    return protocol.Request(kind, path=str(path), value=value, **fields)


class _FakeSysfs(unittest.TestCase):
    """
    A root hub, a blocked peripheral with one interface, a live peripheral,
    and the class/bus views that link them, all in a temporary directory the
    gate's path constants are pointed at.
    """

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        root = self.root = Path(self._d.name)
        self.devices = root / "sys/devices"
        self.hub = self.devices / "pci0/usb1"
        self.usb = self.hub / "1-1"
        self.intf = self.usb / "1-1:1.0"
        self.live = self.hub / "1-2"
        for d, authorized in ((self.hub, "1"), (self.usb, "0"),
                              (self.intf, "1"), (self.live, "1")):
            d.mkdir(parents=True, exist_ok=True)
            (d / "authorized").write_text(authorized + "\n")
        (self.hub / "authorized_default").write_text("1\n")
        (self.intf / "bInterfaceClass").write_text("08\n")
        self.busview = root / "sys/bus/usb/devices"
        self.busview.mkdir(parents=True)
        for d in (self.hub, self.usb, self.intf, self.live):
            os.symlink(d, self.busview / d.name)
        self.cls = root / "sys/class"
        for cls_dir, node, real in (("input", "event5", self.usb),
                                    ("block", "sdz", self.usb)):
            d = self.cls / cls_dir / node
            d.mkdir(parents=True)
            os.symlink(real, d / "device")
        self.dev = root / "dev"
        (self.dev / "input").mkdir(parents=True)
        self.sys_dev_block = root / "sys/dev/block"
        self.sys_dev_block.mkdir(parents=True)
        for attr, value in (
                ("USB_REAL_PREFIX", str(self.devices) + "/"),
                ("USB_LINK_PREFIX", str(self.busview) + "/"),
                ("SYS_CLASS_PREFIX", str(self.cls) + "/"),
                ("INPUT_PREFIX", str(self.dev / "input") + "/"),
                ("BLOCK_PREFIX", str(self.dev) + "/"),
                ("SYS_DEV_BLOCK", str(self.sys_dev_block))):
            patcher = mock.patch.object(gate_server, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.logged = []
        self.gate = gate_server.GateServer(sock=None, log=self.logged.append)

    def assertRefused(self, resp, status=protocol.DENIED, detail=""):
        self.assertEqual(resp.status, status, resp.detail)
        self.assertIn(detail, resp.detail)

    def instance(self, path):
        st = path.stat()
        return st.st_dev, st.st_ino


class GatePathChecksFailClosed(_FakeSysfs):

    def test_paths_that_cannot_be_resolved_are_refused(self):
        self.assertIsNone(self.gate._safe_usb_path("/sys/\0"))
        self.assertIsNone(self.gate._safe_input_path("/dev/input/\0"))
        self.assertIsNone(self.gate._usb_parent_of(Path("/dev/\0")))
        self.assertEqual(self.gate._check_block_path("/dev/\0"),
                         (None, "path cannot be resolved"))

    def test_a_block_node_that_cannot_be_stated_says_why(self):
        (self.dev / "sdz").write_bytes(b"")
        with mock.patch.object(gate_server.os, "stat",
                               side_effect=PermissionError("denied")):
            node, reason = self.gate._check_block_path(str(self.dev / "sdz"))
        self.assertIsNone(node)
        self.assertIn("cannot stat the node", reason)

    def disk(self, name, number=(8, 0), partition=False):
        kernel = self.sys_dev_block / f"{number[0]}:{number[1]}"
        target = self.root / "sys/block-real" / name
        target.mkdir(parents=True)
        if partition:
            (target / "partition").write_text("1\n")
        os.symlink(target, kernel)
        return mock.Mock(st_mode=stat.S_IFBLK | 0o660,
                         st_rdev=os.makedev(*number))

    def test_the_whole_disk_test_reads_the_kernels_record(self):
        st = self.disk("sdz")
        self.assertEqual(self.gate._whole_disk_reason(st, "sdz"), "")
        self.assertIn("is sdz to the kernel, not sdy",
                      self.gate._whole_disk_reason(st, "sdy"))

    def test_a_partition_is_not_a_whole_disk(self):
        st = self.disk("sdz1", number=(8, 1), partition=True)
        self.assertIn("is a partition",
                      self.gate._whole_disk_reason(st, "sdz1"))

    def test_a_kernel_record_that_cannot_be_resolved_is_unregistered(self):
        st = mock.Mock(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 0))
        with mock.patch.object(gate_server.os.path, "realpath",
                               side_effect=OSError("loop")):
            self.assertIn("has no block device",
                          self.gate._whole_disk_reason(st, "sdz"))

    def test_a_class_link_that_cannot_be_resolved_has_no_parent(self):
        real = os.path.realpath

        def realpath(path, *a, **k):
            if str(path).endswith("/device"):
                raise OSError("gone")
            return real(path, *a, **k)
        with mock.patch.object(gate_server.os.path, "realpath",
                               side_effect=realpath):
            self.assertIsNone(self.gate._usb_parent_of(
                self.dev / "input/event5"))

    def test_an_instance_that_vanished_is_not_owned(self):
        gone = self.devices / "pci0/usb1/1-9"
        self.gate._authorized_here.add(str(gone))
        self.gate._instances[str(gone)] = (1, 2)
        self.assertFalse(self.gate._owns_instance(gone))

    def test_attributes_that_cannot_be_read_are_none(self):
        self.assertIsNone(self.gate._read_attr_pinned(
            self.devices / "missing", "authorized"))
        self.assertFalse(self.gate._storage_only(self.devices / "missing"))


class GateMediaScopeFailsClosed(_FakeSysfs):

    def test_a_bus_view_that_cannot_be_listed_records_nothing(self):
        with mock.patch.object(gate_server.os, "listdir",
                               side_effect=OSError("gone")):
            gate = gate_server.GateServer(None, log=self.logged.append,
                                          watch_media=True)
        self.assertEqual(gate._media_hosts, {})

    def test_only_live_storage_only_peripherals_are_recorded(self):
        # 1-2 is live and storage-only; the hub and the interface are not
        # peripherals; 1-1 is blocked.
        (self.live / "1-2:1.0").mkdir()
        (self.live / "1-2:1.0" / "bInterfaceClass").write_text("08\n")
        os.symlink(self.root / "nowhere", self.busview / "1-3")
        gate = gate_server.GateServer(None, log=self.logged.append,
                                      watch_media=True)
        self.assertEqual(set(gate._media_hosts), {str(self.live)})

    def test_an_instance_that_cannot_be_read_is_skipped(self):
        (self.live / "1-2:1.0").mkdir()
        (self.live / "1-2:1.0" / "bInterfaceClass").write_text("08\n")
        with mock.patch.object(gate_server.GateServer, "_instance",
                               side_effect=OSError("gone")):
            gate = gate_server.GateServer(None, log=self.logged.append,
                                          watch_media=True)
            self.assertEqual(gate._media_hosts, {})
            gate._media_hosts[str(self.live)] = (1, 2)
            self.assertFalse(gate._media_host(self.live))


class GateAuthorizationRefusals(_FakeSysfs):

    def test_admission_needs_a_switch_on_and_an_instance(self):
        for value, instance in ((0, (1, 2)), (1, None)):
            resp = self.gate._do_admit(_req(protocol.REQ_ADMIT, self.usb,
                                            value, instance=instance))
            self.assertRefused(resp, protocol.ERROR, "needs a device instance")

    def test_a_device_whose_flag_cannot_be_read_is_an_error(self):
        (self.usb / "authorized").unlink()
        resp = self.gate._do_authorize(_req(protocol.REQ_AUTHORIZE,
                                            self.usb, 1))
        self.assertRefused(resp, protocol.ERROR)
        self.assertEqual(self.gate._authorized_here, set())


class GateInterfaceRefusals(_FakeSysfs):

    def ask(self, path, value):
        return self.gate._do_authorize_interface(
            _req(protocol.REQ_AUTHORIZE_INTERFACE, path, value))

    def test_a_value_other_than_zero_or_one_is_an_error(self):
        self.assertRefused(self.ask(self.intf, 2), protocol.ERROR,
                           "0 or 1")

    def test_a_path_outside_the_usb_tree_is_refused(self):
        self.assertRefused(self.ask(self.root / "etc", 0), detail="not a USB")

    def test_an_interface_of_a_root_hub_is_refused(self):
        hub_intf = self.hub / "1-0:1.0"
        hub_intf.mkdir()
        os.symlink(hub_intf, self.busview / "1-0:1.0")
        self.assertRefused(self.ask(hub_intf, 0), detail="no valid parent")

    def test_unbinding_an_interface_of_a_live_device_is_refused(self):
        live_intf = self.live / "1-2:1.0"
        live_intf.mkdir()
        (live_intf / "authorized").write_text("1\n")
        os.symlink(live_intf, self.busview / "1-2:1.0")
        self.assertRefused(self.ask(live_intf, 0), detail="refusing to unbind")
        self.assertEqual((live_intf / "authorized").read_text(), "1\n")

    def test_a_write_that_fails_is_an_error_and_not_recorded(self):
        with mock.patch.object(gate_server.GateServer, "_write_authorized_at",
                               side_effect=OSError("ENODEV")):
            self.assertRefused(self.ask(self.intf, 0), protocol.ERROR,
                               "ENODEV")
        self.assertEqual(self.gate._interfaces_off, {})

    def test_an_interface_whose_instance_cannot_be_read_is_still_restored(self):
        with mock.patch.object(gate_server.GateServer, "_instance",
                               side_effect=OSError("gone")):
            self.assertTrue(self.ask(self.intf, 0).ok)
        self.assertEqual(self.gate._interfaces_off, {str(self.intf): None})
        self.gate.restore()
        self.assertEqual((self.intf / "authorized").read_text(), "1")


class GateRootHubRefusals(_FakeSysfs):

    def ask(self, path, value):
        return self.gate._do_set_default(
            _req(protocol.REQ_SET_DEFAULT, path, value))

    def test_a_value_outside_the_three_is_an_error(self):
        self.assertRefused(self.ask(self.hub, 3), protocol.ERROR)

    def test_a_path_outside_the_usb_tree_is_refused(self):
        self.assertRefused(self.ask(self.root, 0), detail="path not under")

    def test_a_peripheral_has_no_default_to_set(self):
        self.assertRefused(self.ask(self.usb, 0), detail="belongs to a root")

    def test_a_hub_directory_that_cannot_be_opened_is_an_error(self):
        real_open = os.open

        def refuse(path, flags, *a, **k):
            if str(path) == str(self.hub):
                raise PermissionError("EACCES")
            return real_open(path, flags, *a, **k)
        with mock.patch.object(gate_server.os, "open", side_effect=refuse):
            self.assertRefused(self.ask(self.hub, 0), protocol.ERROR, "EACCES")

    def test_a_hub_never_closed_here_cannot_be_opened(self):
        self.assertRefused(self.ask(self.hub, 1), detail="never closed it")
        self.assertEqual((self.hub / "authorized_default").read_text(), "1\n")

    def test_only_the_previous_value_may_be_restored_and_only_once(self):
        self.assertTrue(self.ask(self.hub, 0).ok)
        self.assertRefused(self.ask(self.hub, 2), detail="only the previous")
        self.assertTrue(self.ask(self.hub, 1).ok)
        self.assertRefused(self.ask(self.hub, 1), detail="never closed it")

    def test_an_unreadable_previous_value_is_restored_as_one(self):
        (self.hub / "authorized_default").write_text("garbage\n")
        self.assertTrue(self.ask(self.hub, 0).ok)
        self.assertEqual(self.gate._closed_defaults, {str(self.hub): 1})

    def test_a_write_that_fails_is_an_error_and_records_nothing(self):
        (self.hub / "authorized_default").unlink()
        (self.hub / "authorized_default").mkdir()
        self.assertRefused(self.ask(self.hub, 0), protocol.ERROR)
        self.assertEqual(self.gate._closed_defaults, {})

    def test_restore_logs_what_it_could_not_put_back(self):
        self.assertTrue(self.ask(self.hub, 0).ok)
        (self.hub / "authorized_default").unlink()
        (self.hub / "authorized_default").mkdir()
        self.gate.restore()
        self.assertTrue(any("could not restore" in line
                            for line in self.logged))


class GateOpenRefusals(_FakeSysfs):

    def node(self):
        """A real character device (/dev/null's numbers) at event5."""
        node = self.dev / "input/event5"
        try:
            os.mknod(node, stat.S_IFCHR | 0o600, os.makedev(1, 3))
        except PermissionError:
            self.skipTest("mknod needs root")
        return node

    def open_input(self, node):
        resp, fd = self.gate._do_open_input(
            _req(protocol.REQ_OPEN_INPUT, node))
        if fd is not None:
            self.addCleanup(os.close, fd)
        return resp, fd

    def test_an_input_node_under_a_blocked_device_is_opened_read_only(self):
        resp, fd = self.open_input(self.node())
        if resp.status == protocol.ERROR:      # a nodev mount
            self.skipTest(resp.detail)
        self.assertTrue(resp.ok and resp.has_fd, resp.detail)
        self.assertEqual(os.O_ACCMODE & fcntl.fcntl(fd, fcntl.F_GETFL),
                         os.O_RDONLY)

    def test_a_node_that_changes_during_the_open_is_refused(self):
        node = self.node()
        regular = mock.Mock(st_mode=stat.S_IFREG, st_rdev=0)
        with mock.patch.object(gate_server.os, "fstat", return_value=regular):
            resp, fd = self.open_input(node)
        if resp.status == protocol.ERROR:
            self.skipTest(resp.detail)
        self.assertRefused(resp, detail="changed during open")
        self.assertIsNone(fd)

    def test_an_input_node_that_cannot_be_opened_is_an_error(self):
        node = self.node()
        real_open = os.open

        def refuse(path, flags, *a, **k):
            if str(path) == str(node):
                raise PermissionError("EACCES")
            return real_open(path, flags, *a, **k)
        with mock.patch.object(gate_server.os, "open", side_effect=refuse):
            resp, fd = self.open_input(node)
        self.assertRefused(resp, protocol.ERROR, "EACCES")
        self.assertIsNone(fd)

    def test_a_disk_outside_quarantine_is_refused(self):
        with mock.patch.object(gate_server.GateServer, "_check_block_path",
                               return_value=(self.dev / "sdz", "")):
            (self.usb / "authorized").write_text("1\n")
            resp, fd = self.gate._do_open_block(
                _req(protocol.REQ_OPEN_BLOCK, self.dev / "sdz"))
        self.assertRefused(resp, detail="not backed by a USB device")
        self.assertIsNone(fd)

    def test_a_disk_that_is_not_a_whole_disk_once_opened_is_refused(self):
        (self.dev / "sdz").write_bytes(b"")
        with mock.patch.object(gate_server.GateServer, "_check_block_path",
                               return_value=(self.dev / "sdz", "")):
            resp, fd = self.gate._do_open_block(
                _req(protocol.REQ_OPEN_BLOCK, self.dev / "sdz"))
        self.assertRefused(resp, detail="not a block device")
        self.assertIsNone(fd)

    def test_a_disk_that_cannot_be_opened_is_an_error(self):
        with mock.patch.object(gate_server.GateServer, "_check_block_path",
                               return_value=(self.dev / "sdz", "")):
            resp, fd = self.gate._do_open_block(
                _req(protocol.REQ_OPEN_BLOCK, self.dev / "sdz"))
        self.assertRefused(resp, protocol.ERROR)
        self.assertIsNone(fd)


class GateFingerprintFailsClosed(_FakeSysfs):

    def fingerprint(self):
        fd = os.open(self.usb, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return self.gate._fingerprint_at(fd)
        finally:
            os.close(fd)

    def test_descriptors_past_the_bound_give_no_fingerprint(self):
        with mock.patch.object(gate_server, "MAX_DESCRIPTOR_BYTES", 4):
            (self.usb / "descriptors").write_bytes(b"\x12" * 18)
            (self.usb / "idVendor").write_text("0951\n")
            (self.usb / "idProduct").write_text("1666\n")
            self.assertIsNone(self.fingerprint())

    def test_no_vendor_gives_no_fingerprint(self):
        (self.usb / "descriptors").write_bytes(b"\x12" * 18)
        (self.usb / "idProduct").write_text("1666\n")
        self.assertIsNone(self.fingerprint())

    def test_no_key_gives_no_fingerprint(self):
        (self.usb / "descriptors").write_bytes(b"\x12" * 18)
        (self.usb / "idVendor").write_text("0951\n")
        (self.usb / "idProduct").write_text("1666\n")
        with mock.patch.object(gate_server.trust_mod, "key_for",
                               return_value=None):
            self.assertIsNone(self.fingerprint())

    def test_an_attribute_that_fails_mid_read_is_none(self):
        fd = os.open(self.usb, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with mock.patch.object(gate_server.os, "fdopen",
                               side_effect=OSError("EIO")):
            self.assertIsNone(self.gate._read_text_at(fd, "authorized"))


class GateServeLoopSurvivesItsPeer(unittest.TestCase):
    """The loop ends on a dead peer and never on a bad request."""

    class Peer:
        def __init__(self, *incoming, send_fails=False):
            self.incoming = list(incoming)
            self.sent = []
            self.send_fails = send_fails

        def recv(self, _size):
            item = self.incoming.pop(0) if self.incoming else b""
            if isinstance(item, Exception):
                raise item
            return item

        def sendmsg(self, parts, *ancillary):
            if self.send_fails:
                raise BrokenPipeError("EPIPE")
            self.sent.append((protocol.Response.decode(parts[0]), ancillary))

    def serve(self, peer):
        logged = []
        gate = gate_server.GateServer(peer, log=logged.append)
        gate.serve_forever()
        return gate, logged

    def test_a_receive_error_ends_the_loop_and_restores(self):
        ping = protocol.Request(protocol.REQ_PING).encode()
        peer = self.Peer(OSError("ECONNRESET"), ping)
        with mock.patch.object(gate_server.GateServer, "restore") as restore:
            self.serve(peer)
        self.assertEqual(peer.incoming, [ping], "kept reading a dead peer")
        self.assertEqual(peer.sent, [])
        restore.assert_called_once_with()

    def test_a_bad_request_is_answered_and_the_loop_goes_on(self):
        ping = protocol.Request(protocol.REQ_PING).encode()
        peer = self.Peer(b"not json", ping)
        self.serve(peer)
        self.assertEqual([r.status for r, _ in peer.sent],
                         [protocol.ERROR, protocol.OK])

    def test_a_bad_request_to_a_dead_peer_ends_the_loop(self):
        ping = protocol.Request(protocol.REQ_PING).encode()
        peer = self.Peer(b"not json", ping, send_fails=True)
        self.serve(peer)
        self.assertEqual(peer.incoming, [ping], "kept reading a dead peer")

    def test_every_request_kind_is_dispatched(self):
        kinds = (protocol.REQ_OPEN_INPUT, protocol.REQ_OPEN_BLOCK)
        peer = self.Peer(*(protocol.Request(k, path="/nonexistent").encode()
                           for k in kinds))
        self.serve(peer)
        self.assertEqual([r.status for r, _ in peer.sent],
                         [protocol.DENIED] * len(kinds))

    def test_the_gates_copy_of_a_sent_descriptor_is_closed(self):
        fd = os.open(os.devnull, os.O_RDONLY)
        peer = self.Peer(protocol.Request(
            protocol.REQ_OPEN_INPUT, path="/dev/input/event5").encode())
        with mock.patch.object(gate_server.GateServer, "_do_open_input",
                               return_value=(protocol.Response(
                                   protocol.OK, has_fd=True), fd)):
            self.serve(peer)
        self.assertEqual(len(peer.sent), 1)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_a_descriptor_already_closed_does_not_end_the_gate(self):
        peer = self.Peer(protocol.Request(
            protocol.REQ_OPEN_INPUT, path="/dev/input/event5").encode())
        with mock.patch.object(gate_server.GateServer, "_do_open_input",
                               return_value=(protocol.Response(
                                   protocol.OK, has_fd=True), 10**6)), \
                mock.patch.object(gate_server.GateServer, "_reply"):
            self.serve(peer)


if __name__ == "__main__":
    unittest.main()
