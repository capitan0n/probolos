"""Security regression scenarios: no real USB devices or root writes required."""
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest import mock

from probolos import agentlink, daemon, descriptors, gate, gate_server
from probolos import ledger, privsep, protocol, quarantine, rules, sysfs, trust
from probolos.gate_client import GateClient


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


class GateLifecycle(unittest.TestCase):
    def test_partial_startup_restores_already_closed_hubs(self):
        writes = []
        def write(hub, value):
            writes.append((hub.name, value))
            if hub.name == "usb2" and value == 0:
                raise OSError("controller disappeared")
        with mock.patch.object(sysfs, "list_root_hubs", return_value=[Path("usb1"), Path("usb2")]), \
             mock.patch.object(sysfs, "get_authorized_default", return_value=1), \
             mock.patch.object(sysfs, "set_authorized_default", side_effect=write):
            with self.assertRaises(OSError):
                with gate.AuthorizationGate(log=lambda *_: None):
                    self.fail("startup must fail")
        self.assertIn(("usb1", 1), writes)

    def test_failed_restore_can_be_retried(self):
        obj = gate.AuthorizationGate(log=lambda *_: None)
        obj._armed = True
        obj._original = {Path("usb1"): 1}
        with mock.patch.object(sysfs, "set_authorized_default", side_effect=[OSError("busy"), None]) as write:
            obj.restore()
            obj.restore()
            self.assertEqual(write.call_count, 2)
            self.assertFalse(obj._armed)


class GateAdmission(unittest.TestCase):
    def setUp(self):
        # Reuse the existing synthetic kernel tree, not its inherited tests.
        from tests.test_audit_followup import GateOpenScope
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


class QuarantineLifetime(unittest.TestCase):
    def setUp(self):
        self.read_fd, self.write_fd = os.pipe()
        os.set_blocking(self.read_fd, False)
        self.addCleanup(os.close, self.write_fd)
        self.order = []
        self.udev = mock.Mock()

    def run_observation(self, collect=None, grab=None):
        with mock.patch.object(quarantine, "pyudev", self.udev), \
             mock.patch.object(quarantine, "find_input_nodes", return_value=["/dev/input/event5"]), \
             mock.patch.object(sysfs, "open_input_node", return_value=self.read_fd), \
             mock.patch.object(quarantine, "_grab", side_effect=grab), \
             mock.patch.object(quarantine, "_ungrab", side_effect=lambda _: self.order.append("ungrab")), \
             mock.patch.object(quarantine, "_collect", side_effect=collect):
            return quarantine.quarantine(Path("unused"),
                authorize_fn=lambda: self.order.append("on"),
                deauthorize_fn=lambda: self.order.append("off"), duration=0.01)

    def test_block_happens_before_ungrab(self):
        self.run_observation()
        self.assertEqual(self.order, ["on", "off", "ungrab"])
        with self.assertRaises(OSError):
            os.fstat(self.read_fd)

    def test_exception_still_blocks_before_ungrab(self):
        with self.assertRaises(RuntimeError):
            self.run_observation(collect=RuntimeError("read failed"))
        self.assertEqual(self.order, ["on", "off", "ungrab"])

    def test_failed_grab_stops_and_blocks_immediately(self):
        obs = self.run_observation(grab=OSError("busy"))
        self.assertTrue(obs.grab_failures)
        self.assertEqual(self.order, ["on", "off"])

    def test_event_buffers_are_bounded(self):
        obs = quarantine.Observation(capture=True)
        with mock.patch.object(quarantine, "MAX_EVENTS", 4):
            for _ in range(10):
                quarantine._record_event(quarantine.EV_KEY, 30, 1, obs, time.monotonic())
        self.assertLessEqual(len(obs.raw_events), 4)
        self.assertLessEqual(len(obs.key_presses), 4)
        self.assertTrue(obs.limit_reached)
        os.close(self.read_fd)

    def test_queued_event_timing_uses_kernel_timestamps(self):
        events = b"".join(struct.pack(quarantine.INPUT_EVENT_FORMAT, 1000, us,
                                     quarantine.EV_KEY, 30, 1) for us in (100000, 900000))
        os.write(self.write_fd, events)
        obs = quarantine.Observation()
        quarantine._collect([self.read_fd], obs, 0.01, wall_start=1000)
        self.assertAlmostEqual(obs.intervals()[0], 0.8)
        os.close(self.read_fd)

    def test_collection_checks_for_late_nodes(self):
        second_read, second_write = os.pipe()
        self.addCleanup(os.close, second_write)
        os.set_blocking(second_read, False)
        with mock.patch.object(quarantine, "pyudev", self.udev), \
             mock.patch.object(quarantine, "find_input_nodes", side_effect=[
                 ["/dev/input/event5"], ["/dev/input/event5", "/dev/input/event6"]
             ]) as discover, \
             mock.patch.object(sysfs, "open_input_node", side_effect=[self.read_fd, second_read]), \
             mock.patch.object(quarantine, "_grab"), \
             mock.patch.object(quarantine, "_ungrab"):
            obs = quarantine.quarantine(Path("unused"), lambda: None,
                                        deauthorize_fn=lambda: None, duration=0.001)
        self.assertEqual(obs.grabbed, ["/dev/input/event5", "/dev/input/event6"])
        for fd in (self.read_fd, second_read):
            with self.assertRaises(OSError):
                os.fstat(fd)


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


class StateReload(unittest.TestCase):
    def test_broken_reload_revokes_cached_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trusted.json"
            path.write_text('{"schema":1,"devices":{}}')
            obj = trust.TrustStore(path)
            obj.devices["stale"] = object()
            path.write_text("[]")
            obj.load()
            self.assertEqual(obj.devices, {})
            self.assertIsNotNone(obj.load_error)

    def test_nonfinite_timestamps_are_rejected(self):
        from tests.test_trust_integrity import good_entry
        for value in (float("inf"), float("nan"), 10 ** 1000):
            data = good_entry()
            data["trusted_at"] = value
            self.assertIsNone(trust.TrustedDevice.from_raw(data["key"], data))


class DescriptorCoverage(unittest.TestCase):
    def device(self, truncated=False):
        # Build explicitly: first config storage, second config HID.
        raw = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x200, 0, 0, 0, 64,
                          0x1234, 0x5678, 0x100, 0, 0, 0, 2)
        for value, cls in ((1, 8), (2, 3)):
            raw += struct.pack("<BBHBBBBB", 9, 2, 18, 1, value, 0, 0x80, 50)
            raw += struct.pack("<BBBBBBBBB", 9, 4, 0, 0, 1, cls, 1, 1, 0)
        ds = descriptors.parse(raw)
        if truncated:
            ds.truncated = "missing tail"
        return sysfs.UsbDevice(Path("unused"), "1-1", "1234", "5678", None,
                              None, None, 1, 2, "12", 0, 0, ds)

    def test_later_configuration_cannot_hide_input_from_storage_guard(self):
        dev = self.device()
        self.assertIn("input", dev.kinds)
        self.assertIn("storage", dev.kinds)
        self.assertEqual(rules.worst(rules.evaluate(dev)), rules.Severity.CRITICAL)

    def test_truncated_descriptors_disable_early_activation(self):
        self.assertFalse(self.device(truncated=True).inspection_safe)

    def test_removed_baseline_port_is_not_ignored_forever(self):
        engine = daemon.Probolos()
        engine.known.add("1-1")
        engine._on_remove("/sys/bus/usb/devices/1-1")
        self.assertNotIn("1-1", engine.known)
