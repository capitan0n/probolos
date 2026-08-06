"""
Regression tests for three "written but never connected" defects.

All three share the dominant bug pattern in this codebase: correct code that
was never wired to the path it was written for.

  1. GateBackend had no authorize_interface, so sysfs.set_interface_authorized
     raised AttributeError under --privsep -- the mode the systemd unit
     mandates.
  2. --list parsed but was never dispatched, so the documented read-only
     inventory command fell through and CLOSED THE GATE instead.
  3. agent.py returned ANSWER_NO when it had no dialog backend at all, so a
     machine without kdialog/zenity silently denied every device rather than
     falling back to the terminal.
"""

import unittest
from unittest import mock

from cerberus import agentlink, gate_client, protocol, sysfs


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
        from cerberus import __main__ as m
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


if __name__ == "__main__":
    unittest.main()
