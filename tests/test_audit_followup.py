"""
Regression tests for the second-pass audit findings.

Each of these is the same failure the project keeps producing: work that is
correct in isolation and never exercised on the path it was written for. The
tests are therefore written against the SEQUENCE, not the predicate.
"""

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


if __name__ == "__main__":
    unittest.main()
