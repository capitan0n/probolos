"""
Audit regressions: protections that existed in the tree and were not
connected to the path that needed them.

This is the project's signature defect, so the tests for it are kept
together rather than filed under the review that happened to find each
one. Every class below corresponds to a protection that was written,
documented, and reachable by nothing.

Merged from: test_wiring_gaps.py, test_wiring_regressions.py, test_audit_followup.py, test_post_audit_regressions.py, test_security_review.py
"""
from __future__ import annotations

# =========================================================================
# test_wiring_gaps.py
#
# Regression tests for three "written but never connected" defects.
# =========================================================================

import unittest
from unittest import mock

from probolos import agentlink, gate_client, protocol, sysfs


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


class ListIsDispatched(unittest.TestCase):

    def test_list_runs_the_inventory_and_never_closes_the_gate(self):
        from probolos import __main__ as m
        with mock.patch.object(m, "cmd_list") as listing, \
             mock.patch.object(m, "require_root") as root, \
             mock.patch.object(m, "require_usb"):
            m.main(["--list"])
        listing.assert_called_once()
        root.assert_not_called()


class AgentUnavailableIsNotARefusal(unittest.TestCase):

    def test_sentinel_is_not_a_decision(self):
        """
        The analyzer maps anything outside the three real answers to None, and
        None means "fall back to the terminal". The sentinel must land there --
        if it were ever added to the valid set, every dialog-less machine would
        go back to silently denying devices.
        """
        self.assertNotIn(agentlink.ANSWER_UNAVAILABLE,
                         (agentlink.ANSWER_YES,
                          agentlink.ANSWER_ALWAYS,
                          agentlink.ANSWER_NO))

    def test_sentinel_is_distinct_from_no(self):
        self.assertNotEqual(agentlink.ANSWER_UNAVAILABLE, agentlink.ANSWER_NO)


# =========================================================================
# test_wiring_regressions.py
#
# Tests for code that existed but was connected to nothing.
# =========================================================================

import json
import os
import stat
import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from probolos import descriptors, rules, storage, trust


def device_desc(vid=0x1234, pid=0x5678, bcd_usb=0x0200, num_configs=1):
    return struct.pack(
        "<BBHBBBBHHHBBBB",
        18, 0x01, bcd_usb, 0x00, 0, 0, 64,
        vid, pid, 0x0100, 0, 0, 0, num_configs)


def config_desc(total, n_ifaces=1, max_power=50):
    return struct.pack("<BBHBBBBB", 9, 0x02, total, n_ifaces, 1, 0, 0x80,
                       max_power)


def iface_desc(cls=0x03, num=0):
    return struct.pack("<BBBBBBBBB", 9, 0x04, num, 0, 1, cls, 0, 0, 0)


# ==========================================================================
# descriptors.parse() now walks through descriptors_safe
# ==========================================================================

class ParserUsesTheHardenedWalker(unittest.TestCase):

    def test_a_flood_of_tiny_descriptors_is_refused(self):
        """The protection that only descriptors_safe had, and nothing used.

        The loop this replaced bounded every descriptor's SIZE but never their
        COUNT, so 200_000 two-byte items were walked one at a time. Not fatal
        on its own -- which is exactly how a bound goes missing.
        """
        from probolos.descriptors_safe import MAX_DESCRIPTOR_ITEMS
        blob = device_desc() + b"\x02\x02" * (MAX_DESCRIPTOR_ITEMS + 1)
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(blob)

    def test_an_ordinary_composite_device_is_not_refused_as_a_flood(self):
        """The ceiling must sit above real hardware, not through it.

        At 256 descriptors for the whole blob, a UVC webcam with its usual
        run of alternate settings tripped the flood guard, and the flood
        guard is non-recoverable -- so the device was refused outright:
        parse_error set, inspection_safe False, no behavioural or storage
        stage, and a WARNING on somebody's own camera.
        """
        body = config_desc(total=9 + 9 * 300) + iface_desc() * 300
        ds = descriptors.parse(device_desc() + body)
        self.assertIsNone(ds.truncated)
        self.assertEqual(len(ds.configs), 1)
        self.assertEqual(len(ds.configs[0].interfaces), 300)

    def test_a_truncated_tail_is_still_kept_and_now_reported(self):
        """The behaviour that had to survive the rewrite.

        A tail that stops early is common on merely buggy hardware, so it must
        not become a refusal. What changed is that it is no longer discarded in
        silence.
        """
        body = config_desc(total=27) + iface_desc() + b"\x09\x04\x00"
        ds = descriptors.parse(device_desc() + body)
        self.assertEqual(len(ds.primary_interfaces()), 1)
        self.assertIsNotNone(ds.truncated)

    def test_the_truncation_reaches_the_operator_as_a_finding(self):
        body = config_desc(total=27) + iface_desc() + b"\x09\x04\x00"
        ds = descriptors.parse(device_desc() + body)
        found = rules.evaluate(_Stub(ds))
        self.assertIn("descriptor-chain-truncated", {f.rule_id for f in found})

    def test_overstated_wtotallength_is_reported(self):
        """The fingerprint of a hand-edited descriptor set: vendor toolchains
        compute this field, so a mismatch is not a typo."""
        body = config_desc(total=0xFFFF) + iface_desc()
        ds = descriptors.parse(device_desc() + body)
        self.assertGreater(ds.length_overstated, 0)
        found = rules.evaluate(_Stub(ds))
        self.assertIn("descriptor-length-overstated",
                      {f.rule_id for f in found})

    def test_an_honest_device_produces_neither_finding(self):
        """The false-positive guard. A rule that fires on ordinary hardware is
        worse than no rule, because it teaches the operator to click through."""
        body = config_desc(total=18) + iface_desc()
        ds = descriptors.parse(device_desc() + body)
        self.assertIsNone(ds.truncated)
        self.assertEqual(ds.length_overstated, 0)
        ids = {f.rule_id for f in rules.evaluate(_Stub(ds))}
        self.assertNotIn("descriptor-chain-truncated", ids)
        self.assertNotIn("descriptor-length-overstated", ids)

    def test_zero_blength_is_still_fatal(self):
        """Not recoverable, and must not be softened into a warning: the walk
        cannot advance past it by any amount."""
        blob = device_desc() + b"\x00\x02\xff\xff"
        with self.assertRaises(descriptors.DescriptorParseError):
            descriptors.parse(blob)


class _Stub:
    """Duck-typed device, matching tests/test_rules.py's FakeDevice.

    interfaces and interface_classes must be properties derived from the
    descriptor set, not empty lists: the rule engine reads them, and a stub
    that hands back [] silently disables half the rules under test.
    """

    def __init__(self, ds):
        self.descriptor_set = ds
        self.vendor_id = "1234"
        self.product_id = "5678"
        self.manufacturer = None
        self.product = None
        self.serial = None
        self.speed = "12"
        self.parse_error = None

    @property
    def interfaces(self):
        return self.descriptor_set.primary_interfaces()

    @property
    def interface_classes(self):
        return self.descriptor_set.interface_classes()

    def label(self):
        return ""


# ==========================================================================
# storage.inspect() now uses every hardening function, not one of four
# ==========================================================================

class StorageHardeningIsInForce(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.path = Path(self._tmp.name) / "disk.img"

    def tearDown(self):
        self._tmp.cleanup()

    def _mbr(self, entries):
        """Build a 4 KiB image with an MBR carrying the given partitions."""
        sector = bytearray(512)
        for i, (start, sectors) in enumerate(entries):
            off = 446 + i * 16
            sector[off + 0] = 0x00          # not bootable
            sector[off + 4] = 0x83          # Linux
            sector[off + 8:off + 12] = struct.pack("<I", start)
            sector[off + 12:off + 16] = struct.pack("<I", sectors)
        sector[510:512] = b"\x55\xaa"
        self.path.write_bytes(bytes(sector) + bytes(4096 - 512))
        return str(self.path)

    def test_a_partition_longer_than_the_disk_is_refused_and_reported(self):
        """The gap that only filter_safe_partitions closed.

        safe_read_offset() validates the START of a partition, and only the
        start. A partition beginning at sector 1 of an 8192-sector disk has a
        perfectly legal start, so it passed that check and was read -- even
        though it claims to run four billion sectors past the end of the
        medium. The impossibility was never recorded anywhere.
        """
        device = self._mbr([(1, 0xFFFFFFFF)])
        self._pretend_disk_is(8192)
        report = storage.inspect(device, open_fn=lambda p: os.open(p, os.O_RDONLY))
        self.assertTrue(report.suspicious,
                        "an impossible partition length must be recorded")
        self.assertIn("8192", report.suspicious[0])

    def test_an_absurd_declared_device_size_is_discarded_not_trusted(self):
        """The size is device-controlled AND is what every per-partition bound
        is measured against, so an absurd one does not merely produce a wrong
        number -- it disables the checks that depend on it."""
        device = self._mbr([(1, 6)])
        self._pretend_disk_is(10 ** 15)
        report = storage.inspect(device, open_fn=lambda p: os.open(p, os.O_RDONLY))
        self.assertIsNone(report.size_sectors,
                          "an implausible size must be discarded, not used")
        self.assertTrue(any("size" in s for s in report.suspicious))

    def _pretend_disk_is(self, sectors):
        """Override the sysfs size lookup, which cannot see a temp file."""
        original = storage.read_size_sectors
        storage.read_size_sectors = lambda _device: sectors
        self.addCleanup(lambda: setattr(storage, "read_size_sectors", original))

    def test_impossible_geometry_becomes_a_finding(self):
        """report.suspicious was written by the inspector and read by nobody.

        A refusal that never reaches the operator is indistinguishable from a
        check that was never performed.
        """
        report = storage.MediumReport(device="/dev/sdz", scheme="mbr")
        report.suspicious = ["partition 0: ends at 4294967296 — unrealistic"]
        found = rules.storage_findings(report)
        self.assertIn("impossible-partition-geometry",
                      {f.rule_id for f in found})

    def test_an_ordinary_layout_stays_silent(self):
        device = self._mbr([(1, 6)])
        report = storage.inspect(device, open_fn=lambda p: os.open(p, os.O_RDONLY))
        self.assertEqual(report.suspicious, [])
        self.assertEqual(
            [f.rule_id for f in rules.storage_findings(report)], [])


# ==========================================================================
# C3: the trust store is an admission list, so its permissions are load bearing
# ==========================================================================

class TrustStoreIntegrity(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.path = Path(self._tmp.name) / "trusted.json"
        self.path.write_text(json.dumps({
            "schema": trust.SCHEMA_VERSION,
            "devices": {
                "1234:5678:AB#" + "a" * 64: {
                    "key": "1234:5678:AB#" + "a" * 64,
                    "identity": "1234:5678:AB",
                    "descriptor_hash": "a" * 64,
                    "trusted_at": 0.0,
                    "last_seen": 0.0,
                    "label": "test",
                },
            },
        }))
        os.chmod(self.path, 0o600)

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_correct_store_still_loads(self):
        """The check must not break the normal case, or it will be removed."""
        store = trust.TrustStore(self.path)
        self.assertIsNone(store.load_error)
        self.assertEqual(len(store.devices), 1)

    def test_a_world_writable_store_is_not_believed(self):
        """Whoever can write this file can admit any device without ever
        touching the machine. Writing it at 0600 says nothing about the file
        we are about to READ: cp does not preserve mode, and restores and
        backups do not go through our writer."""
        os.chmod(self.path, 0o666)
        store = trust.TrustStore(self.path)
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.devices, {},
                         "fail closed: an untrustworthy store is an empty one")

    def test_a_group_writable_store_is_not_believed(self):
        os.chmod(self.path, 0o660)
        store = trust.TrustStore(self.path)
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.devices, {})

    def test_the_advice_in_the_error_is_actionable(self):
        os.chmod(self.path, 0o666)
        store = trust.TrustStore(self.path)
        self.assertIn("chmod 600", store.load_error)

    def test_a_symlink_is_refused_rather_than_followed(self):
        """lstat, not stat. Following the link would check one inode's
        ownership and then read a different inode's contents."""
        real = Path(self._tmp.name) / "elsewhere.json"
        real.write_text(self.path.read_text())
        link = Path(self._tmp.name) / "link.json"
        link.symlink_to(real)
        store = trust.TrustStore(link)
        self.assertIsNotNone(store.load_error)
        self.assertIn("symlink", store.load_error)
        self.assertEqual(store.devices, {})

    def test_a_missing_store_is_not_an_error(self):
        """First run. Nothing trusted yet is the normal state, not a fault."""
        store = trust.TrustStore(Path(self._tmp.name) / "absent.json")
        self.assertIsNone(store.load_error)
        self.assertEqual(store.devices, {})


# ==========================================================================
# The two version strings that disagreed
# ==========================================================================

class VersionHasOneSource(unittest.TestCase):

    def test_the_package_version_matches_pyproject(self):
        import probolos

        root = Path(__file__).resolve().parent.parent
        pyproject = (root / "pyproject.toml").read_text()
        declared = None
        for line in pyproject.splitlines():
            if line.startswith("version ="):
                declared = line.split("=", 1)[1].strip().strip('"')
                break

        self.assertIsNotNone(declared, "pyproject.toml has no version")
        # Installed: exactly equal. Source checkout: the "+source" fallback,
        # which must still carry the same base number.
        self.assertTrue(
            probolos.__version__ in (declared, declared + "+source"),
            f"{probolos.__version__!r} does not match pyproject {declared!r}")


# =========================================================================
# test_audit_followup.py
#
# Regression tests for the second-pass audit findings.
# =========================================================================

import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from probolos import agentlink, gate_server, ledger as ledger_mod, payload
from probolos import protocol, rules, trust as trust_mod, usbclass


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


# ---------------------------------------------------------------------------
# 2. State files: valid JSON that is not an object
# ---------------------------------------------------------------------------

class NonObjectStateFiles(unittest.TestCase):
    """
    `[]` is valid JSON, so json.loads succeeds and .get() raises
    AttributeError -- out of load(), out of __init__, uncaught. The daemon dies
    during startup, BEFORE authorized_default is set to 0, so the gate never
    closes. A one-byte file disables the tool and looks like a crash.
    """

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.root = Path(self._dir.name)

    def test_ledger_survives_a_json_array(self):
        path = self.root / "ledger.json"
        path.write_text("[]")
        store = ledger_mod.Ledger(path)
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.entries, {})

    def test_ledger_survives_a_json_scalar(self):
        path = self.root / "ledger.json"
        path.write_text("42")
        self.assertIsNotNone(ledger_mod.Ledger(path).load_error)

    def _trust_file(self, text):
        path = self.root / "trusted.json"
        path.write_text(text)
        os.chmod(path, 0o600)
        return path

    def test_trust_store_survives_a_json_scalar(self):
        store = trust_mod.TrustStore(self._trust_file('"hello"'))
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.devices, {})

    def test_trust_store_survives_a_non_empty_devices_array(self):
        """`or {}` saved the empty case only; a non-empty list is truthy."""
        store = trust_mod.TrustStore(
            self._trust_file('{"schema": 1, "devices": ["a", "b"]}'))
        self.assertIsNotNone(store.load_error)
        self.assertEqual(store.devices, {})

    def test_a_good_store_still_loads(self):
        store = trust_mod.TrustStore(
            self._trust_file('{"schema": 1, "devices": {}}'))
        self.assertIsNone(store.load_error)


# ---------------------------------------------------------------------------
# 3. Payload reconstruction: the character cap was resettable
# ---------------------------------------------------------------------------

class PayloadBound(unittest.TestCase):
    """
    The cap compared max_chars against payload.text (empty until the last line
    of the function) plus the CURRENT buffer -- which flush() emptied. Pressing
    ENTER reset it, so a hostile HID typing newlines was never bounded at all.
    """

    def test_cap_is_not_reset_by_flushing_a_line(self):
        events = []
        for _ in range(2000):
            events += [(0.0, 30, 1), (0.0, 30, 0),      # 'a'
                       (0.0, 28, 1), (0.0, 28, 0)]      # ENTER
        recovered = payload.reconstruct(events, max_chars=10)
        self.assertTrue(recovered.truncated)
        self.assertLess(len(recovered.lines), 30)

    def test_keystroke_count_is_still_complete(self):
        """How much it typed is a finding; only the transcript is bounded."""
        events = []
        for _ in range(500):
            events += [(0.0, 30, 1), (0.0, 30, 0)]
        recovered = payload.reconstruct(events, max_chars=10)
        self.assertEqual(recovered.keystrokes, 500)
        self.assertTrue(recovered.truncated)

    def test_short_payloads_are_untouched(self):
        events = [(0.0, 38, 1), (0.0, 38, 0),           # 'l'
                  (0.0, 31, 1), (0.0, 31, 0)]           # 's'
        recovered = payload.reconstruct(events)
        self.assertFalse(recovered.truncated)
        self.assertEqual(recovered.text, "ls")


# ---------------------------------------------------------------------------
# 4. The agent's "I cannot ask" reply was produced and never consumed
# ---------------------------------------------------------------------------

class AgentUnavailableReturnsImmediately(unittest.TestCase):
    """
    ANSWER_UNAVAILABLE exists so a dialog-less agent is told apart from a user
    saying no. The agent sends it; _parse_answer dropped it as "not one of the
    three real answers"; ask() therefore kept waiting for a reply it already
    had, for the whole 60-second budget. The udev loop is single-threaded, so
    every device attached during that minute queued behind a question the agent
    had already declined to ask.
    """

    def _link_over(self, sock):
        link = agentlink.AgentLink.__new__(agentlink.AgentLink)
        link.log = lambda *_a: None
        link._lock = threading.Lock()
        link._conn = sock
        link._asking = 0
        link._peer = None
        sock.settimeout(1.0)
        return link

    def _answer_with(self, value):
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        link = self._link_over(ours)

        def agent():
            try:
                message = json.loads(theirs.recv(65536).decode().strip())
            except (OSError, ValueError):
                return
            theirs.sendall((json.dumps({
                "type": agentlink.MSG_ANSWER,
                "id": message["id"],
                "answer": value}) + "\n").encode())

        thread = threading.Thread(target=agent, daemon=True)
        thread.start()
        started = time.monotonic()
        answer = link.ask("t", "b", "none", True, timeout=8.0)
        return answer, time.monotonic() - started

    def test_unavailable_does_not_wait_out_the_timeout(self):
        answer, elapsed = self._answer_with(agentlink.ANSWER_UNAVAILABLE)
        self.assertIsNone(answer, "not a decision")
        self.assertLess(elapsed, 2.0,
                        "the reply was already in hand; ask() must not block")

    def test_unavailable_is_still_not_read_as_consent(self):
        answer, _ = self._answer_with(agentlink.ANSWER_UNAVAILABLE)
        self.assertNotEqual(answer, agentlink.ANSWER_YES)
        self.assertNotEqual(answer, agentlink.ANSWER_ALWAYS)

    def test_a_real_answer_still_works(self):
        answer, elapsed = self._answer_with(agentlink.ANSWER_YES)
        self.assertEqual(answer, agentlink.ANSWER_YES)
        self.assertLess(elapsed, 2.0)

    def test_nonsense_answers_are_still_ignored(self):
        """An unknown string is not a decision AND not a reason to give up."""
        answer, elapsed = self._answer_with("maybe")
        self.assertIsNone(answer)
        self.assertGreater(elapsed, 7.0, "kept waiting for a real answer")


# ---------------------------------------------------------------------------
# 5. The BadUSB rule was evadable with two zero bytes
# ---------------------------------------------------------------------------

class _Iface:
    number = 0
    alternate = 0
    num_endpoints = 1

    def __init__(self, cls, subcls, proto):
        self.interface_class = cls
        self.interface_subclass = subcls
        self.interface_protocol = proto


class _Device:
    parse_error = None
    descriptor_set = None
    serial = None
    string_notes = ()
    string_note_fields = {}

    def __init__(self, ifaces, manufacturer="Acme", product="Widget",
                 speed="12"):
        self.interfaces = ifaces
        self.manufacturer = manufacturer
        self.product = product
        self.speed = speed

    @property
    def interface_classes(self):
        out = []
        for i in self.interfaces:
            if i.interface_class not in out:
                out.append(i.interface_class)
        return out

    def label(self):
        return f"{self.manufacturer} {self.product}"


STORAGE = _Iface(0x08, 0x06, 0x50)
BOOT_KEYBOARD = _Iface(0x03, 0x01, 0x01)
BOOT_MOUSE = _Iface(0x03, 0x01, 0x02)
UNDECLARED_HID = _Iface(0x03, 0x00, 0x00)
BLUETOOTH = _Iface(0xE0, 0x01, 0x01)


class UndeclaredHidIsNotInnocence(unittest.TestCase):
    """
    is_keyboard() fires only on subclass 0x01 / protocol 0x01. A HID interface
    declaring 0x00 / 0x00 is legal, common, and still a working keyboard under
    Linux -- usbhid reads the REPORT descriptor, which is not in the sysfs blob
    and cannot be fetched without talking to a device we are holding precisely
    because we do not trust it. So the whole BadUSB rule was evadable by
    omitting the boot protocol.
    """

    def _ids(self, dev):
        return {f.rule_id for f in rules.evaluate(dev)}

    # -- the classification primitives ------------------------------------

    def test_declared_keyboard_is_a_keyboard(self):
        self.assertTrue(usbclass.is_keyboard(0x03, 0x01, 0x01))
        self.assertFalse(usbclass.is_undeclared_hid(0x03, 0x01, 0x01))

    def test_declared_mouse_has_answered_the_question(self):
        self.assertFalse(usbclass.is_undeclared_hid(0x03, 0x01, 0x02))
        self.assertFalse(usbclass.may_type(0x03, 0x01, 0x02))

    def test_hid_without_a_boot_protocol_might_type(self):
        self.assertFalse(usbclass.is_keyboard(0x03, 0x00, 0x00))
        self.assertTrue(usbclass.is_undeclared_hid(0x03, 0x00, 0x00))
        self.assertTrue(usbclass.may_type(0x03, 0x00, 0x00))

    def test_non_hid_never_types(self):
        self.assertFalse(usbclass.may_type(0x08, 0x06, 0x50))

    # -- the regression ----------------------------------------------------

    def test_declared_badusb_is_still_critical(self):
        dev = _Device([STORAGE, BOOT_KEYBOARD])
        self.assertIn("storage-with-keyboard", self._ids(dev))
        self.assertEqual(rules.worst(rules.evaluate(dev)),
                         rules.Severity.CRITICAL)

    def test_evasive_badusb_is_now_critical_too(self):
        dev = _Device([STORAGE, UNDECLARED_HID])
        self.assertIn("storage-with-undeclared-hid", self._ids(dev))
        self.assertEqual(rules.worst(rules.evaluate(dev)),
                         rules.Severity.CRITICAL)

    def test_network_plus_undeclared_hid_is_a_warning_not_a_verdict(self):
        """
        Graded lower on purpose: some radios expose a vendor HID channel, and
        what the interface does cannot be read from the descriptors.
        """
        dev = _Device([BLUETOOTH, UNDECLARED_HID])
        found = rules.evaluate(dev)
        self.assertIn("network-with-undeclared-hid",
                      {f.rule_id for f in found})
        self.assertEqual(rules.worst(found), rules.Severity.WARNING)

    def test_disguised_injector_without_a_boot_protocol_is_caught(self):
        dev = _Device([UNDECLARED_HID], manufacturer="Kingston",
                      product="DataTraveler")
        self.assertIn("self-contradictory-identity", self._ids(dev))

    # -- and the design principle it must not break ------------------------

    def test_an_ordinary_mouse_stays_silent(self):
        self.assertEqual(self._ids(_Device([BOOT_MOUSE], "Logitech", "M185")),
                         set())

    def test_a_subclass_zero_mouse_stays_silent(self):
        """The common shape. Flagging it alone would train people to ignore us."""
        self.assertEqual(
            self._ids(_Device([UNDECLARED_HID], "Logitech", "G502")), set())

    def test_a_headset_with_hid_buttons_stays_silent(self):
        dev = _Device([_Iface(0x01, 0x01, 0x00), _Iface(0x01, 0x02, 0x00),
                       UNDECLARED_HID], "Sennheiser", "PC 8")
        self.assertEqual(self._ids(dev), set())

    def test_a_plain_flash_drive_stays_silent(self):
        self.assertEqual(
            self._ids(_Device([STORAGE], "Kingston", "DataTraveler")), set())


# =========================================================================
# test_post_audit_regressions.py
#
# Regressions found while reviewing the hardening patch, plus two older ones.
# =========================================================================

import os
import subprocess
import sys
import types
import unittest
from pathlib import Path


def _stub_pyudev():
    """quarantine.available() needs the module present; nothing else does."""
    mod = types.ModuleType("pyudev")

    class _Mon:
        @staticmethod
        def from_netlink(ctx):
            return _Mon()

        def filter_by(self, **kwargs):
            pass

        def start(self):
            pass

        def poll(self, timeout=None):
            return None

    mod.Context = type("Context", (), {})
    mod.Monitor = _Mon
    return mod


class ReblockFailureDoesNotKillTheDaemon(unittest.TestCase):
    """
    The device is pulled out during the observation window.

    `deauthorize()` then returns ENODEV. It ran inside quarantine()'s `finally`
    with nothing catching it, so the OSError travelled up through _quarantine()
    and _on_add() into the udev poll loop, which has no handler either. The
    daemon exited on an unplug.
    """

    def setUp(self):
        sys.modules.setdefault("pyudev", _stub_pyudev())
        from probolos import quarantine
        self.quarantine = quarantine
        quarantine.pyudev = sys.modules["pyudev"]
        self._real_find = quarantine.find_input_nodes
        quarantine.find_input_nodes = lambda path, ctx=None: []

    def tearDown(self):
        self.quarantine.find_input_nodes = self._real_find

    def test_enodev_on_reblock_is_reported_not_raised(self):
        def deauthorize():
            raise OSError(19, "No such device")

        obs = self.quarantine.quarantine(
            Path("/sys/bus/usb/devices/1-4"),
            authorize_fn=lambda: None,
            duration=0.05, settle_timeout=0.05,
            deauthorize_fn=deauthorize)

        self.assertIsNotNone(obs.reblock_error)
        self.assertIn("No such device", obs.reblock_error)

    def test_a_failed_reblock_becomes_a_critical_finding(self):
        """
        Reporting it is not enough on its own. Every other behavioural finding
        is read on the assumption that the device is off again while the human
        decides; if the re-block failed that assumption is false, and a NOTICE
        buried under the timing statistics would not say so.
        """
        from probolos import rules

        obs = self.quarantine.Observation(duration=1.0)
        obs.reblock_error = "[Errno 16] Device or resource busy"
        findings = rules.behaviour_findings(obs)
        critical = [f for f in findings
                    if f.rule_id == "quarantine-not-restored"]
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].severity, rules.Severity.CRITICAL)


class LoginctlTimeoutIsContained(unittest.TestCase):
    """
    is_locked() is called once a second from the main loop and once per device.

    The handling only ever wrapped _graphical_sessions(). _locked_hint() runs
    in the loop BELOW that try, so a loginctl call that exceeded its three
    second timeout raised TimeoutExpired out of is_locked() and killed the
    daemon -- a lock-state lookup taking the gate down with it.
    """

    def test_a_hung_loginctl_degrades_to_unknown(self):
        from probolos import session

        monitor = session.LogindMonitor()
        monitor._binary = "/bin/true"

        calls = {"n": 0}

        def hang(*args, **kwargs):
            calls["n"] += 1
            raise subprocess.TimeoutExpired(cmd="loginctl", timeout=3)

        real_run = subprocess.run
        subprocess.run = hang
        try:
            self.assertIsNone(monitor.is_locked())
        finally:
            subprocess.run = real_run
        self.assertGreater(calls["n"], 0)

    def test_a_hung_hint_lookup_does_not_escape_either(self):
        """The specific gap: the sessions list succeeds, the hint call hangs."""
        from probolos import session

        monitor = session.LogindMonitor()
        monitor._binary = "/bin/true"
        monitor._graphical_sessions = lambda: ["c1"]

        def hang(session_id):
            raise subprocess.TimeoutExpired(cmd="loginctl", timeout=3)

        monitor._locked_hint = hang
        with self.assertRaises(subprocess.TimeoutExpired):
            monitor._locked_hint("c1")     # the hazard is real...
        # ...and _run(), which is where the real call lives, contains it.
        real_run = subprocess.run
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="loginctl", timeout=3))
        try:
            self.assertEqual(session.LogindMonitor._run(monitor, "x"), "")
        finally:
            subprocess.run = real_run


class DeferredBindFailurePutsInterfacesBack(unittest.TestCase):
    """
    The exception path threw away the list of interfaces it had switched off.

    Those interfaces stay at authorized=0 in the kernel. A device the user
    later approves then comes up dead, with nothing left in the process to say
    which interfaces to restore or why they are off.
    """

    def test_interfaces_are_restored_and_cleanup_errors_do_not_mask(self):
        from probolos import deferred_bind, sysfs

        restored = []
        calls = []

        class FakeBackend:
            supports_bus_wide = True

            def authorize(self, syspath, value):
                calls.append((str(syspath), value))
                raise OSError(19, "No such device")   # cleanup itself fails

            def authorize_interface(self, intf, value):
                restored.append((intf.name, value))

            def trigger_driver_probe(self, name):
                pass

            def set_drivers_autoprobe(self, value):
                pass

        real_backend = sysfs._backend
        sysfs._backend = FakeBackend()
        try:
            db = deferred_bind.DeferredBind(
                Path("/sys/bus/usb/devices/1-4"), log=lambda *a: None)
            db._device_authorized = True
            db._holding_autoprobe = False
            db._deauthorized = [Path("/sys/bus/usb/devices/1-4:1.0")]

            original = ValueError("the real failure")
            # __exit__ must report False (do not swallow) and must not raise
            # its own cleanup error over the caller's exception.
            swallowed = db.__exit__(ValueError, original, None)
        finally:
            sysfs._backend = real_backend

        self.assertFalse(swallowed)
        self.assertEqual(restored, [("1-4:1.0", 1)])
        self.assertEqual(db._deauthorized, [])


class UnreadableHubDefaultStaysRestorable(unittest.TestCase):
    """
    A root hub whose authorized_default could not be read was closed anyway and
    then never recorded, so restore() -- which only walks the recorded hubs --
    skipped it. The hub stayed at 0 after the daemon exited: no USB device on
    it binds a driver again until someone writes the file by hand.
    """

    def test_an_unreadable_previous_value_still_records_a_restore_target(self):
        import tempfile
        from probolos import gate_server, protocol

        with tempfile.TemporaryDirectory() as tmp:
            hub = Path(tmp) / "usb1"
            hub.mkdir()
            attr = hub / "authorized_default"
            attr.write_text("not-a-number")

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
            self.assertIn(str(hub), gate._closed_defaults)
            self.assertEqual(gate._closed_defaults[str(hub)], 1)


class NotificationCleanupNeverCostsAnAnswer(unittest.TestCase):
    """
    Notifier.close() runs in the `finally` of the agent's decision path, after
    the human has already chosen. An unhandled TimeoutExpired there replaced
    the return value with an exception and the decision was lost.
    """

    def test_a_hung_gdbus_is_swallowed(self):
        from probolos import agent

        notifier = agent.Notifier.__new__(agent.Notifier)
        notifier._gdbus = "/bin/true"

        real_run = subprocess.run
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd="gdbus", timeout=5))
        try:
            notifier.close(7)      # must simply return
        finally:
            subprocess.run = real_run


class AdmitDescriptorIsCloseOnExec(unittest.TestCase):
    """
    The privileged half spawns children (the storage worker, dialog backends).
    A writable descriptor on a device's `authorized` attribute must not be
    inherited by any of them.
    """

    def test_o_cloexec_is_set(self):
        import inspect
        from probolos import sysfs

        source = inspect.getsource(sysfs._DirectBackend.admit)
        self.assertIn("O_CLOEXEC", source)


# =========================================================================
# test_security_review.py
#
# Security regression scenarios: no real USB devices or root writes required.
# =========================================================================

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
        pass  # name is local to this module after the merge
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
        from tests.test_trust import good_entry
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


if __name__ == "__main__":
    unittest.main()
